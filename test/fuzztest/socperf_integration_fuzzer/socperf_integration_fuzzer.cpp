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
 * @file socperf_integration_fuzzer.cpp
 * @brief Comprehensive fuzzing driver for SocPerf module integration testing.
 *
 * Coverage targets:
 * - SocPerfClient API fuzzing (all 10 public APIs)
 * - SocPerfConfig validation APIs
 * - Boundary condition testing
 * - Race condition simulation
 * - Complex state transitions
 * - Error path coverage
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <set>
#include <list>
#include <atomic>
#include <functional>

// SocPerf headers
#include "socperf_client.h"
#include "socperf_action_type.h"
#include "socperf.h"
#include "socperf_common.h"
#include "socperf_config.h"
#include "socperf_thread_wrap.h"
#include "socperf_server.h"
#include "socperf_log.h"

namespace FuzzUtils {

// ============================================================================
// Constants (G.CNS.02: Use named constants)
// ============================================================================

// Input size constraints
constexpr int32_t MIN_INPUT_SIZE = 4;
constexpr int32_t MAX_INPUT_SIZE = 8192;

// String size constraints
constexpr int32_t DEFAULT_STRING_LENGTH = 256;
constexpr int32_t MAX_STRING_LENGTH = 1024;

// Vector size constraints
constexpr int32_t DEFAULT_VECTOR_SIZE = 20;
constexpr int32_t MAX_VECTOR_SIZE = 100;

// Resource and command ID ranges
constexpr int32_t MAX_CMD_ID = 50000;
constexpr int32_t MAX_THERMAL_LEVEL = 1000;
constexpr int32_t MAX_CLIENT_ID = 100;

// Stress test iterations
constexpr int32_t STRESS_ITERATIONS = 50;
constexpr int32_t RAPID_CALL_COUNT = 100;

// Test case selectors
constexpr uint8_t TEST_CASE_INIT = 0;
constexpr uint8_t TEST_CASE_PERF_REQUEST = 1;
constexpr uint8_t TEST_CASE_PERF_REQUEST_EX = 2;
constexpr uint8_t TEST_CASE_POWER_LIMIT_BOOST = 3;
constexpr uint8_t TEST_CASE_THERMAL_LIMIT_BOOST = 4;
constexpr uint8_t TEST_CASE_LIMIT_REQUEST = 5;
constexpr uint8_t TEST_CASE_SET_REQUEST_STATUS = 6;
constexpr uint8_t TEST_CASE_SET_THERMAL_LEVEL = 7;
constexpr uint8_t TEST_CASE_REQUEST_DEVICE_MODE = 8;
constexpr uint8_t TEST_CASE_REQUEST_CMD_ID_COUNT = 9;
constexpr uint8_t TEST_CASE_RESET_CLIENT = 10;
constexpr uint8_t TEST_CASE_CONFIG_ISVALIDRESID = 11;
constexpr uint8_t TEST_CASE_CONFIG_ISGOVERRESID = 12;
constexpr uint8_t TEST_CASE_COMBINED_SEQUENCE = 13;
constexpr uint8_t TEST_CASE_BOUNDARY_VALUES = 14;
constexpr uint8_t TEST_CASE_RACE_SIMULATION = 15;
constexpr uint8_t TEST_CASE_ERROR_PATHS = 16;
constexpr uint8_t TEST_CASE_STRING_FUZZING = 17;
constexpr uint8_t TEST_CASE_VECTOR_FUZZING = 18;
constexpr uint8_t TEST_CASE_STATE_MACHINE = 19;
constexpr uint8_t TEST_CASE_COUNT = 20;

// Common test values
constexpr int32_t TEST_CMD_ID_BASE = 1000;
constexpr int32_t TEST_CMD_ID_GAME = 2000;
constexpr int32_t TEST_CMD_ID_THERMAL = 3000;
constexpr int32_t TEST_CMD_ID_SPECIAL = 10000;

// Thermal levels
constexpr int32_t THERMAL_LEVEL_NORMAL = 0;
constexpr int32_t THERMAL_LEVEL_WARNING = 1;
constexpr int32_t THERMAL_LEVEL_SEVERE = 2;
constexpr int32_t THERMAL_LEVEL_EXTREME = 3;

// Client IDs
constexpr int32_t CLIENT_ID_THERMAL = 1;
constexpr int32_t CLIENT_ID_POWER = 2;

// Resource IDs
constexpr int32_t RES_ID_CPU = 1000;
constexpr int32_t RES_ID_GPU = 2000;
constexpr int32_t RES_ID_DDR = 3000;
constexpr int32_t RES_ID_NPU = 4000;

// ============================================================================
// Inline Validation Functions
// ============================================================================

inline bool CheckSize(size_t size, size_t minSize)
{
    return size >= minSize;
}

inline bool CheckPointer(const void* ptr)
{
    return ptr != nullptr;
}

inline bool CheckOffset(size_t offset, size_t size, size_t typeSize)
{
    return offset + typeSize <= size;
}

// ============================================================================
// DataExtractor Class (G.EXP.09: Variables declared when needed)
// ============================================================================

class DataExtractor {
public:
    explicit DataExtractor(const uint8_t* data, size_t size)
        : data_(data), size_(size), offset_(0) {}

    ~DataExtractor() = default;

    uint8_t ExtractUInt8()
    {
        const uint8_t* ptr = SafeRead(sizeof(uint8_t));
        if (ptr == nullptr) {
            return 0;
        }
        return *ptr;
    }

    int8_t ExtractInt8()
    {
        const uint8_t* ptr = SafeRead(sizeof(int8_t));
        if (ptr == nullptr) {
            return 0;
        }
        int8_t value = 0;
        memcpy(&value, ptr, sizeof(int8_t));
        return value;
    }

    uint16_t ExtractUInt16()
    {
        const uint8_t* ptr = SafeRead(sizeof(uint16_t));
        if (ptr == nullptr) {
            return 0;
        }
        uint16_t value = 0;
        memcpy(&value, ptr, sizeof(uint16_t));
        return value;
    }

    int16_t ExtractInt16()
    {
        const uint8_t* ptr = SafeRead(sizeof(int16_t));
        if (ptr == nullptr) {
            return 0;
        }
        int16_t value = 0;
        memcpy(&value, ptr, sizeof(int16_t));
        return value;
    }

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

    int64_t ExtractInt64()
    {
        const uint8_t* ptr = SafeRead(sizeof(int64_t));
        if (ptr == nullptr) {
            return 0;
        }
        int64_t value = 0;
        memcpy(&value, ptr, sizeof(int64_t));
        return value;
    }

    uint64_t ExtractUInt64()
    {
        const uint8_t* ptr = SafeRead(sizeof(uint64_t));
        if (ptr == nullptr) {
            return 0;
        }
        uint64_t value = 0;
        memcpy(&value, ptr, sizeof(uint64_t));
        return value;
    }

    bool ExtractBool()
    {
        const uint8_t* ptr = SafeRead(sizeof(uint8_t));
        if (ptr == nullptr) {
            return false;
        }
        return *ptr != 0;
    }

    float ExtractFloat()
    {
        const uint8_t* ptr = SafeRead(sizeof(float));
        if (ptr == nullptr) {
            return 0.0f;
        }
        float value = 0.0f;
        memcpy(&value, ptr, sizeof(float));
        return value;
    }

    std::string ExtractString(size_t maxLen = DEFAULT_STRING_LENGTH)
    {
        if (maxLen == 0 || maxLen > MAX_STRING_LENGTH) {
            maxLen = MAX_STRING_LENGTH;
        }

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

    std::string ExtractStringWithLen(size_t len, size_t maxLen = DEFAULT_STRING_LENGTH)
    {
        if (len > maxLen) {
            len = maxLen;
        }
        if (offset_ + len > size_) {
            len = size_ - offset_;
        }
        if (len == 0) {
            return "";
        }
        const uint8_t* ptr = SafeRead(len);
        if (ptr == nullptr) {
            return "";
        }
        return std::string(reinterpret_cast<const char*>(ptr), len);
    }

    std::vector<int32_t> ExtractInt32Vector(size_t maxElements = DEFAULT_VECTOR_SIZE)
    {
        std::vector<int32_t> result;
        if (maxElements == 0 || maxElements > MAX_VECTOR_SIZE) {
            maxElements = MAX_VECTOR_SIZE;
        }

        if (!CanExtract(sizeof(int32_t))) {
            return result;
        }
        int32_t numElements = ExtractInt32();
        if (numElements < 0) {
            numElements = -numElements;
        }
        if (numElements > static_cast<int32_t>(maxElements)) {
            numElements = static_cast<int32_t>(maxElements);
        }

        for (int32_t i = 0; i < numElements; ++i) {
            if (!CanExtract(sizeof(int32_t))) {
                break;
            }
            result.push_back(ExtractInt32());
        }

        return result;
    }

    std::vector<int64_t> ExtractInt64Vector(size_t maxElements = DEFAULT_VECTOR_SIZE)
    {
        std::vector<int64_t> result;
        if (maxElements == 0 || maxElements > MAX_VECTOR_SIZE) {
            maxElements = MAX_VECTOR_SIZE;
        }

        if (!CanExtract(sizeof(int32_t))) {
            return result;
        }
        int32_t numElements = ExtractInt32();
        if (numElements < 0) {
            numElements = -numElements;
        }
        if (numElements > static_cast<int32_t>(maxElements)) {
            numElements = static_cast<int32_t>(maxElements);
        }

        for (int32_t i = 0; i < numElements; ++i) {
            if (!CanExtract(sizeof(int64_t))) {
                break;
            }
            result.push_back(ExtractInt64());
        }

        return result;
    }

    std::vector<std::string> ExtractStringVector(size_t maxStrings = 5, size_t maxLen = 100)
    {
        std::vector<std::string> result;
        if (maxStrings == 0) {
            return result;
        }
        for (size_t i = 0; i < maxStrings && HasMore(); ++i) {
            result.push_back(ExtractString(maxLen));
        }
        return result;
    }

    bool HasMore() const
    {
        return offset_ < size_;
    }

    size_t Remaining() const
    {
        return size_ - offset_;
    }

    void Reset()
    {
        offset_ = 0;
    }

    size_t GetOffset() const
    {
        return offset_;
    }

    size_t GetSize() const
    {
        return size_;
    }

    DataExtractor(const DataExtractor&) = delete;
    DataExtractor& operator=(const DataExtractor&) = delete;
    DataExtractor(DataExtractor&&) = delete;
    DataExtractor& operator=(DataExtractor&&) = delete;

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
using namespace OHOS::SOCPERF;

// ============================================================================
// Global State Management
// ============================================================================

static std::mutex g_fuzzMutex;
static bool g_systemInitialized = false;
static std::atomic<uint32_t> g_callCounter(0);
static std::atomic<uint32_t> g_errorCounter(0);

// ============================================================================
// Test Helper Functions
// ============================================================================

bool InitializeSystem()
{
    std::lock_guard<std::mutex> lock(g_fuzzMutex);
    if (g_systemInitialized) {
        return true;
    }

    auto& config = SocPerfConfig::GetInstance();
    if (config.Init()) {
        g_systemInitialized = true;
        return true;
    }
    return false;
}

SocPerfClient& GetSocPerfClient()
{
    return SocPerfClient::GetInstance();
}

// ============================================================================
// Test Case Implementations
// ============================================================================

void TestCaseInit(DataExtractor& extractor)
{
    (void)extractor;
    g_systemInitialized = false;
    InitializeSystem();
    InitializeSystem();
    InitializeSystem();

    auto& client1 = SocPerfClient::GetInstance();
    auto& client2 = SocPerfClient::GetInstance();
    auto& client3 = SocPerfClient::GetInstance();
    (void)client1;
    (void)client2;
    (void)client3;
}

void TestCasePerfRequest(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    int32_t cmdId = extractor.ExtractInt32();
    std::string msg = extractor.ExtractString(DEFAULT_STRING_LENGTH);

    client.PerfRequest(cmdId, msg);
    g_callCounter++;

    client.PerfRequest(0, "zero");
    client.PerfRequest(1, "one");
    client.PerfRequest(-1, "negative");
    client.PerfRequest(INT32_MAX, "max");
    client.PerfRequest(INT32_MIN, "min");

    client.PerfRequest(TEST_CMD_ID_BASE, "base");
    client.PerfRequest(TEST_CMD_ID_GAME, "game");
    client.PerfRequest(TEST_CMD_ID_THERMAL, "thermal");
    client.PerfRequest(TEST_CMD_ID_SPECIAL, "special");
    client.PerfRequest(MAX_CMD_ID, "max_range");

    client.PerfRequest(cmdId, "");
    client.PerfRequest(cmdId, "a");
    client.PerfRequest(cmdId, "test");
    client.PerfRequest(cmdId, std::string(1024, 'x'));
    client.PerfRequest(cmdId, std::string(4096, 'y'));

    for (int32_t i = 0; i < RAPID_CALL_COUNT; i++) {
        client.PerfRequest(cmdId + i, "rapid");
    }
}

void TestCasePerfRequestEx(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    int32_t cmdId = extractor.ExtractInt32();
    bool onOffTag = extractor.ExtractBool();
    std::string msg = extractor.ExtractString(DEFAULT_STRING_LENGTH);

    client.PerfRequestEx(cmdId, onOffTag, msg);
    g_callCounter++;

    client.PerfRequestEx(cmdId, true, "on");
    client.PerfRequestEx(cmdId, false, "off");
    client.PerfRequestEx(cmdId, true, "on_again");
    client.PerfRequestEx(cmdId, false, "off_again");

    client.PerfRequestEx(0, onOffTag, msg);
    client.PerfRequestEx(-1, onOffTag, msg);
    client.PerfRequestEx(INT32_MAX, onOffTag, msg);
    client.PerfRequestEx(INT32_MIN, onOffTag, msg);

    for (int32_t i = 0; i < STRESS_ITERATIONS; i++) {
        client.PerfRequestEx(cmdId, i % 2 == 0, "toggle");
    }
}

void TestCasePowerLimitBoost(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    bool onOffTag = extractor.ExtractBool();
    std::string msg = extractor.ExtractString(DEFAULT_STRING_LENGTH);

    client.PowerLimitBoost(onOffTag, msg);
    g_callCounter++;

    client.PowerLimitBoost(true, "boost_on");
    client.PowerLimitBoost(false, "boost_off");
    client.PowerLimitBoost(true, "boost_on_again");
    client.PowerLimitBoost(false, "boost_off_again");

    for (int32_t i = 0; i < STRESS_ITERATIONS; i++) {
        client.PowerLimitBoost(i % 2 == 0, "stress_toggle");
    }

    client.PowerLimitBoost(onOffTag, "");
    client.PowerLimitBoost(onOffTag, "short");
    client.PowerLimitBoost(onOffTag, std::string(512, 'p'));
    client.PowerLimitBoost(onOffTag, std::string(1024, 'P'));
}

void TestCaseThermalLimitBoost(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    bool onOffTag = extractor.ExtractBool();
    std::string msg = extractor.ExtractString(DEFAULT_STRING_LENGTH);

    client.ThermalLimitBoost(onOffTag, msg);
    g_callCounter++;

    client.ThermalLimitBoost(true, "thermal_boost_on");
    client.ThermalLimitBoost(false, "thermal_boost_off");
    client.ThermalLimitBoost(true, "thermal_boost_on_again");
    client.ThermalLimitBoost(false, "thermal_boost_off_again");

    for (int32_t i = 0; i < STRESS_ITERATIONS; i++) {
        client.ThermalLimitBoost(i % 2 == 0, "thermal_stress_toggle");
    }

    client.ThermalLimitBoost(onOffTag, "");
    client.ThermalLimitBoost(onOffTag, "short_thermal");
    client.ThermalLimitBoost(onOffTag, std::string(512, 't'));
}

void TestCaseLimitRequest(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    int32_t clientId = extractor.ExtractInt32();
    std::vector<int32_t> tags = extractor.ExtractInt32Vector(DEFAULT_VECTOR_SIZE);
    std::vector<int64_t> configs = extractor.ExtractInt64Vector(DEFAULT_VECTOR_SIZE);
    std::string msg = extractor.ExtractString(DEFAULT_STRING_LENGTH);

    client.LimitRequest(clientId, tags, configs, msg);
    g_callCounter++;

    client.LimitRequest(0, tags, configs, msg);
    client.LimitRequest(-1, tags, configs, msg);
    client.LimitRequest(1, tags, configs, msg);
    client.LimitRequest(CLIENT_ID_THERMAL, tags, configs, msg);
    client.LimitRequest(CLIENT_ID_POWER, tags, configs, msg);
    client.LimitRequest(INT32_MAX, tags, configs, msg);
    client.LimitRequest(INT32_MIN, tags, configs, msg);

    std::vector<int32_t> emptyTags;
    std::vector<int64_t> emptyConfigs;
    client.LimitRequest(clientId, emptyTags, emptyConfigs, "empty_arrays");

    std::vector<int32_t> singleTag = { 1 };
    std::vector<int64_t> singleConfig = { 100 };
    client.LimitRequest(clientId, singleTag, singleConfig, "single_element");

    std::vector<int32_t> moreTags = { 1, 2, 3 };
    std::vector<int64_t> fewerConfigs = { 100 };
    client.LimitRequest(clientId, moreTags, fewerConfigs, "mismatched");

    std::vector<int32_t> largeTags(MAX_VECTOR_SIZE, 1);
    std::vector<int64_t> largeConfigs(MAX_VECTOR_SIZE, 1000);
    client.LimitRequest(clientId, largeTags, largeConfigs, "large_arrays");

    std::vector<int32_t> resTags = { RES_ID_CPU, RES_ID_GPU, RES_ID_DDR, RES_ID_NPU };
    std::vector<int64_t> resConfigs = { 1000, 2000, 3000, 4000 };
    client.LimitRequest(clientId, resTags, resConfigs, "resource_tags");
}

void TestCaseSetRequestStatus(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    bool status = extractor.ExtractBool();
    std::string msg = extractor.ExtractString(DEFAULT_STRING_LENGTH);

    client.SetRequestStatus(status, msg);
    g_callCounter++;

    client.SetRequestStatus(true, "enable");
    client.SetRequestStatus(false, "disable");
    client.SetRequestStatus(true, "enable_again");
    client.SetRequestStatus(false, "disable_again");

    for (int32_t i = 0; i < STRESS_ITERATIONS; i++) {
        client.SetRequestStatus(i % 2 == 0, "rapid_toggle");
    }

    client.SetRequestStatus(status, "");
    client.SetRequestStatus(status, "short");
    client.SetRequestStatus(status, std::string(512, 's'));
}

void TestCaseSetThermalLevel(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    int32_t level = extractor.ExtractInt32();

    client.SetThermalLevel(level);
    g_callCounter++;

    client.SetThermalLevel(THERMAL_LEVEL_NORMAL);
    client.SetThermalLevel(THERMAL_LEVEL_WARNING);
    client.SetThermalLevel(THERMAL_LEVEL_SEVERE);
    client.SetThermalLevel(THERMAL_LEVEL_EXTREME);

    client.SetThermalLevel(0);
    client.SetThermalLevel(-1);
    client.SetThermalLevel(1);
    client.SetThermalLevel(INT32_MAX);
    client.SetThermalLevel(INT32_MIN);

    client.SetThermalLevel(MAX_THERMAL_LEVEL);
    client.SetThermalLevel(-MAX_THERMAL_LEVEL);

    for (int32_t i = 0; i <= 10; i++) {
        client.SetThermalLevel(i);
    }
    for (int32_t i = 10; i >= -10; i--) {
        client.SetThermalLevel(i);
    }
}

void TestCaseRequestDeviceMode(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    std::string mode = extractor.ExtractString(64);
    bool status = extractor.ExtractBool();

    client.RequestDeviceMode(mode, status);
    g_callCounter++;

    client.RequestDeviceMode("game", true);
    client.RequestDeviceMode("game", false);
    client.RequestDeviceMode("video", true);
    client.RequestDeviceMode("video", false);
    client.RequestDeviceMode("camera", true);
    client.RequestDeviceMode("camera", false);
    client.RequestDeviceMode("performance", true);
    client.RequestDeviceMode("performance", false);
    client.RequestDeviceMode("powersave", true);
    client.RequestDeviceMode("powersave", false);
    client.RequestDeviceMode("normal", true);
    client.RequestDeviceMode("normal", false);

    client.RequestDeviceMode("", status);
    client.RequestDeviceMode("a", status);
    client.RequestDeviceMode("ab", status);

    client.RequestDeviceMode(std::string(128, 'm'), status);
    client.RequestDeviceMode(std::string(256, 'M'), status);

    client.RequestDeviceMode("mode_with_underscore", status);
    client.RequestDeviceMode("mode-with-dash", status);
    client.RequestDeviceMode("mode.with.dot", status);
    client.RequestDeviceMode("mode@with@at", status);

    std::string modes[] = { "game", "video", "camera", "performance" };
    for (int32_t i = 0; i < STRESS_ITERATIONS; i++) {
        client.RequestDeviceMode(modes[i % 4], i % 2 == 0);
    }
}

void TestCaseRequestCmdIdCount(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    std::string msg = extractor.ExtractString(DEFAULT_STRING_LENGTH);

    std::string result = client.RequestCmdIdCount(msg);
    g_callCounter++;

    result = client.RequestCmdIdCount("");
    result = client.RequestCmdIdCount("test");
    result = client.RequestCmdIdCount("query");
    result = client.RequestCmdIdCount("statistics");
    result = client.RequestCmdIdCount(std::string(512, 'c'));

    client.PerfRequest(TEST_CMD_ID_BASE, "generate_count");
    client.PerfRequest(TEST_CMD_ID_BASE + 1, "generate_count_2");
    client.PerfRequest(TEST_CMD_ID_BASE + 2, "generate_count_3");
    result = client.RequestCmdIdCount("after_activity");
}

void TestCaseResetClient(DataExtractor& extractor)
{
    (void)extractor;
    SocPerfClient& client = GetSocPerfClient();

    client.ResetClient();
    g_callCounter++;

    client.PerfRequest(TEST_CMD_ID_BASE, "after_reset_1");
    client.SetThermalLevel(THERMAL_LEVEL_NORMAL);
    client.PowerLimitBoost(true, "boost_after_reset");

    client.ResetClient();

    client.PerfRequest(TEST_CMD_ID_BASE + 1, "after_second_reset");
    client.SetThermalLevel(THERMAL_LEVEL_WARNING);

    for (int32_t i = 0; i < 5; i++) {
        client.ResetClient();
        client.PerfRequest(TEST_CMD_ID_BASE + i, "rapid_reset");
    }
}

void TestCaseConfigIsValidResId(DataExtractor& extractor)
{
    auto& config = SocPerfConfig::GetInstance();

    int32_t resId = extractor.ExtractInt32();
    volatile bool result = config.IsValidResId(resId);
    (void)result;
    g_callCounter++;

    config.IsValidResId(0);
    config.IsValidResId(1);
    config.IsValidResId(-1);
    config.IsValidResId(999);
    config.IsValidResId(1000);
    config.IsValidResId(5999);
    config.IsValidResId(6000);
    config.IsValidResId(INT32_MAX);
    config.IsValidResId(INT32_MIN);

    for (int32_t i = 1000; i <= 1100; i++) {
        config.IsValidResId(i);
    }
    for (int32_t i = 5900; i <= 6000; i++) {
        config.IsValidResId(i);
    }
}

void TestCaseConfigIsGovResId(DataExtractor& extractor)
{
    auto& config = SocPerfConfig::GetInstance();

    int32_t resId = extractor.ExtractInt32();
    volatile bool result = config.IsGovResId(resId);
    (void)result;
    g_callCounter++;

    config.IsGovResId(0);
    config.IsGovResId(1);
    config.IsGovResId(-1);
    config.IsGovResId(999);
    config.IsGovResId(1000);
    config.IsGovResId(5999);
    config.IsGovResId(6000);
    config.IsGovResId(INT32_MAX);
    config.IsGovResId(INT32_MIN);

    for (int32_t i = 0; i <= 5000; i += 100) {
        config.IsGovResId(i);
    }
}

void TestCaseCombinedSequence(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    uint8_t sequenceLength = extractor.ExtractUInt8() % 20 + 5;

    for (uint8_t i = 0; i < sequenceLength && extractor.HasMore(); i++) {
        uint8_t op = extractor.ExtractUInt8() % 12;

        switch (op) {
            case 0:
                client.PerfRequest(extractor.ExtractInt32(), extractor.ExtractString(64));
                break;
            case 1:
                client.PerfRequestEx(extractor.ExtractInt32(),
                    extractor.ExtractBool(), extractor.ExtractString(64));
                break;
            case 2:
                client.PowerLimitBoost(extractor.ExtractBool(), extractor.ExtractString(64));
                break;
            case 3:
                client.ThermalLimitBoost(extractor.ExtractBool(), extractor.ExtractString(64));
                break;
            case 4:
                client.LimitRequest(extractor.ExtractInt32(),
                    extractor.ExtractInt32Vector(5),
                    extractor.ExtractInt64Vector(5),
                    extractor.ExtractString(64));
                break;
            case 5:
                client.SetRequestStatus(extractor.ExtractBool(), extractor.ExtractString(64));
                break;
            case 6:
                client.SetThermalLevel(extractor.ExtractInt32());
                break;
            case 7:
                client.RequestDeviceMode(extractor.ExtractString(32), extractor.ExtractBool());
                break;
            case 8:
                client.RequestCmdIdCount(extractor.ExtractString(64));
                break;
            case 9:
                client.ResetClient();
                break;
            case 10:
                SocPerfConfig::GetInstance().IsValidResId(extractor.ExtractInt32());
                break;
            case 11:
                SocPerfConfig::GetInstance().IsGovResId(extractor.ExtractInt32());
                break;
            default:
                break;
        }
        g_callCounter++;
    }
}

void TestCaseBoundaryValues(DataExtractor& extractor)
{
    (void)extractor;
    SocPerfClient& client = GetSocPerfClient();

    client.PerfRequest(INT32_MAX, "max");
    client.PerfRequest(INT32_MIN, "min");
    client.PerfRequest(0, "zero");
    client.PerfRequest(-1, "negative_one");
    client.PerfRequest(1, "one");

    client.SetThermalLevel(INT32_MAX);
    client.SetThermalLevel(INT32_MIN);
    client.SetThermalLevel(0);
    client.SetThermalLevel(-2147483647);
    client.SetThermalLevel(2147483647);

    client.PerfRequest(1, "");
    client.PerfRequest(1, std::string(1, 'a'));
    client.PerfRequest(1, std::string(255, 'b'));
    client.PerfRequest(1, std::string(256, 'c'));
    client.PerfRequest(1, std::string(1023, 'd'));
    client.PerfRequest(1, std::string(1024, 'e'));
    client.PerfRequest(1, std::string(4095, 'f'));
    client.PerfRequest(1, std::string(4096, 'g'));

    std::vector<int32_t> emptyTags;
    std::vector<int64_t> emptyConfigs;
    client.LimitRequest(0, emptyTags, emptyConfigs, "empty");

    std::vector<int32_t> singleTag = { 0 };
    std::vector<int64_t> singleConfig = { 0 };
    client.LimitRequest(0, singleTag, singleConfig, "single");

    std::vector<int32_t> maxTags(MAX_VECTOR_SIZE, 0);
    std::vector<int64_t> maxConfigs(MAX_VECTOR_SIZE, 0);
    client.LimitRequest(0, maxTags, maxConfigs, "max_size");

    client.PerfRequest(1, "\0\0\0");
    client.PerfRequest(1, "\n\t\r");
    client.PerfRequest(1, "\"\'\\");
    client.PerfRequest(1, "\x01\x02\x03");

    g_callCounter++;
}

void TestCaseRaceSimulation(DataExtractor& extractor)
{
    (void)extractor;
    SocPerfClient& client = GetSocPerfClient();

    for (int32_t i = 0; i < STRESS_ITERATIONS; i++) {
        client.SetRequestStatus(true, "race_enable");
        client.SetRequestStatus(false, "race_disable");

        client.PowerLimitBoost(true, "race_power_on");
        client.PowerLimitBoost(false, "race_power_off");
        client.ThermalLimitBoost(true, "race_thermal_on");
        client.ThermalLimitBoost(false, "race_thermal_off");

        client.SetThermalLevel(i % 10);

        std::string modes[] = { "game", "video", "camera" };
        client.RequestDeviceMode(modes[i % 3], true);
        client.RequestDeviceMode(modes[i % 3], false);

        client.PerfRequest(i, "race_request");
        client.PerfRequestEx(i, true, "race_ex_on");
        client.PerfRequestEx(i, false, "race_ex_off");

        g_callCounter++;
    }

    for (int32_t i = 0; i < 20; i++) {
        std::vector<int32_t> tags = { 1000 + i };
        std::vector<int64_t> configs = { 100 * i };
        client.LimitRequest(i % 5, tags, configs, "race_limit");
    }
}

void TestCaseErrorPaths(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    client.ResetClient();

    client.PerfRequest(-999, "after_reset");
    client.PerfRequestEx(-999, true, "after_reset_ex");
    client.LimitRequest(-1, {}, {}, "after_reset_limit");
    client.SetThermalLevel(-999);

    client.SetRequestStatus(false, "disable_for_error_test");
    client.PerfRequest(1, "should_be_blocked");
    client.PerfRequestEx(1, true, "should_be_blocked_ex");
    client.LimitRequest(1, {1}, {1}, "should_be_blocked_limit");

    client.SetRequestStatus(true, "re-enable");
    client.PerfRequest(1, "after_re-enable");

    client.SetThermalLevel(99999);
    client.SetThermalLevel(-99999);
    client.SetThermalLevel(0);

    client.RequestCmdIdCount("before");
    client.PerfRequest(1, "between");
    client.RequestCmdIdCount("after");

    for (int32_t i = 0; i < 10; i++) {
        client.SetRequestStatus(i % 2 == 0, "rapid_status");
        client.PerfRequest(i, "during_status_change");
    }

    g_callCounter++;
}

void TestCaseStringFuzzing(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    int32_t cmdId = extractor.ExtractInt32();

    std::vector<std::string> testStrings = {
        extractor.ExtractString(32),
        extractor.ExtractString(64),
        extractor.ExtractString(128),
        extractor.ExtractString(256),
        extractor.ExtractString(512),
        extractor.ExtractStringWithLen(extractor.Remaining()),
    };

    for (const auto& str : testStrings) {
        client.PerfRequest(cmdId, str);
        client.PerfRequestEx(cmdId, true, str);
        client.PowerLimitBoost(true, str);
        client.ThermalLimitBoost(true, str);
        client.SetRequestStatus(true, str);
        client.RequestDeviceMode(str, true);
        client.RequestCmdIdCount(str);

        std::vector<int32_t> tags = { 1 };
        std::vector<int64_t> configs = { 100 };
        client.LimitRequest(0, tags, configs, str);

        g_callCounter++;
    }

    std::string patterns[] = {
        "",
        " ",
        "  ",
        "\t",
        "\n",
        "\r\n",
        "\0",
        "\x00\x01\x02",
        "中文测试",
        "日本語テスト",
        "한글테스트",
        "<>\"'&",
        "%s%s%s",
        "$(ls)",
        "'; DROP TABLE--",
    };

    for (const auto& pattern : patterns) {
        client.PerfRequest(cmdId, pattern);
        client.RequestCmdIdCount(pattern);
        g_callCounter++;
    }
}

void TestCaseVectorFuzzing(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    size_t tagCount = extractor.ExtractUInt8() % (MAX_VECTOR_SIZE + 1);
    size_t configCount = extractor.ExtractUInt8() % (MAX_VECTOR_SIZE + 1);

    std::vector<int32_t> tags;
    std::vector<int64_t> configs;

    for (size_t i = 0; i < tagCount && extractor.HasMore(); i++) {
        tags.push_back(extractor.ExtractInt32());
    }

    for (size_t i = 0; i < configCount && extractor.HasMore(); i++) {
        configs.push_back(extractor.ExtractInt64());
    }

    std::string msg = extractor.ExtractString(128);
    int32_t clientId = extractor.ExtractInt32();

    client.LimitRequest(clientId, tags, configs, msg);
    g_callCounter++;

    std::vector<int32_t> sizes[] = {
        {},
        { 1 },
        { 1, 2 },
        { 1, 2, 3, 4, 5 },
        { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 },
    };

    for (const auto& sizeVec : sizes) {
        std::vector<int64_t> configVec(sizeVec.size(), 100);
        client.LimitRequest(clientId, sizeVec, configVec, "size_test");
        g_callCounter++;
    }

    std::vector<int32_t> extremeTags = {
        0, 1, -1, INT32_MAX, INT32_MIN,
        1000, 2000, 3000, 4000, 5000, 5999
    };
    std::vector<int64_t> extremeConfigs = {
        0, 1, -1, INT64_MAX, INT64_MIN,
        100, 200, 300, 400, 500,
        0x7FFFFFFFFFFFFFFF, 0x8000000000000000
    };

    client.LimitRequest(clientId, extremeTags, extremeConfigs, "extreme_values");
    g_callCounter++;
}

void TestCaseStateMachine(DataExtractor& extractor)
{
    SocPerfClient& client = GetSocPerfClient();

    bool initialStatus = extractor.ExtractBool();
    int32_t initialLevel = extractor.ExtractInt32() % 10;

    client.SetRequestStatus(initialStatus, "initial_state");
    client.SetThermalLevel(initialLevel);

    uint8_t numTransitions = extractor.ExtractUInt8() % 30 + 10;

    for (uint8_t i = 0; i < numTransitions && extractor.HasMore(); i++) {
        uint8_t transition = extractor.ExtractUInt8() % 8;

        switch (transition) {
            case 0:
                client.SetRequestStatus(true, "transition_enable");
                break;
            case 1:
                client.SetRequestStatus(false, "transition_disable");
                break;
            case 2:
                client.SetThermalLevel((i % 10) + 1);
                break;
            case 3:
                client.SetThermalLevel(std::max(0, (i % 10) - 5));
                break;
            case 4:
                client.PowerLimitBoost(i % 2 == 0, "transition_power");
                break;
            case 5:
                client.ThermalLimitBoost(i % 2 == 0, "transition_thermal");
                break;
            case 6: {
                    std::string modes[] = { "game", "video", "camera", "normal" };
                    client.RequestDeviceMode(modes[i % 4], i % 2 == 0);
                }
                break;
            case 7:
                client.PerfRequest(TEST_CMD_ID_BASE + i, "transition_request");
                break;
        }

        if (i % 10 == 9) {
            client.ResetClient();
            client.SetRequestStatus(true, "reset_recovery");
        }

        g_callCounter++;
    }

    client.SetRequestStatus(true, "final_state");
    client.SetThermalLevel(0);
}

// ============================================================================
// Main Fuzz Entry Point
// ============================================================================

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < MIN_INPUT_SIZE) {
        return 0;
    }

    if (size > MAX_INPUT_SIZE) {
        return 0;
    }

    DataExtractor extractor(data, size);

    if (!InitializeSystem()) {
        return 0;
    }

    uint8_t testCase = extractor.ExtractUInt8() % TEST_CASE_COUNT;

    switch (testCase) {
        case TEST_CASE_INIT:
            TestCaseInit(extractor);
            break;
        case TEST_CASE_PERF_REQUEST:
            TestCasePerfRequest(extractor);
            break;
        case TEST_CASE_PERF_REQUEST_EX:
            TestCasePerfRequestEx(extractor);
            break;
        case TEST_CASE_POWER_LIMIT_BOOST:
            TestCasePowerLimitBoost(extractor);
            break;
        case TEST_CASE_THERMAL_LIMIT_BOOST:
            TestCaseThermalLimitBoost(extractor);
            break;
        case TEST_CASE_LIMIT_REQUEST:
            TestCaseLimitRequest(extractor);
            break;
        case TEST_CASE_SET_REQUEST_STATUS:
            TestCaseSetRequestStatus(extractor);
            break;
        case TEST_CASE_SET_THERMAL_LEVEL:
            TestCaseSetThermalLevel(extractor);
            break;
        case TEST_CASE_REQUEST_DEVICE_MODE:
            TestCaseRequestDeviceMode(extractor);
            break;
        case TEST_CASE_REQUEST_CMD_ID_COUNT:
            TestCaseRequestCmdIdCount(extractor);
            break;
        case TEST_CASE_RESET_CLIENT:
            TestCaseResetClient(extractor);
            break;
        case TEST_CASE_CONFIG_ISVALIDRESID:
            TestCaseConfigIsValidResId(extractor);
            break;
        case TEST_CASE_CONFIG_ISGOVERRESID:
            TestCaseConfigIsGovResId(extractor);
            break;
        case TEST_CASE_COMBINED_SEQUENCE:
            TestCaseCombinedSequence(extractor);
            break;
        case TEST_CASE_BOUNDARY_VALUES:
            TestCaseBoundaryValues(extractor);
            break;
        case TEST_CASE_RACE_SIMULATION:
            TestCaseRaceSimulation(extractor);
            break;
        case TEST_CASE_ERROR_PATHS:
            TestCaseErrorPaths(extractor);
            break;
        case TEST_CASE_STRING_FUZZING:
            TestCaseStringFuzzing(extractor);
            break;
        case TEST_CASE_VECTOR_FUZZING:
            TestCaseVectorFuzzing(extractor);
            break;
        case TEST_CASE_STATE_MACHINE:
            TestCaseStateMachine(extractor);
            break;
        default:
            break;
    }

    return 0;
}
