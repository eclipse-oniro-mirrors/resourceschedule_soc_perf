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
 * @file socperf_integration_fuzzer.cpp
 * @brief Comprehensive fuzzing driver for SocPerf module integration testing.
 */

#include <securec.h>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

// SocPerf headers
#include "socperf.h"
#include "socperf_action_type.h"
#include "socperf_client.h"
#include "socperf_common.h"
#include "socperf_config.h"
#include "socperf_log.h"
#include "socperf_server.h"
#include "socperf_thread_wrap.h"

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
constexpr int32_t STRESS_LOOP_MEDIUM = 20;
constexpr int32_t STRESS_LOOP_LARGE = 50;

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

// String length constants (G.CNS.02)
constexpr size_t STRING_LEN_SMALL = 32;
constexpr size_t STRING_LEN_MEDIUM = 64;
constexpr size_t STRING_LEN_LARGE = 128;
constexpr size_t STRING_LEN_XLARGE = 256;
constexpr size_t STRING_LEN_XXLARGE = 512;

// Loop boundary constants (G.CNS.02)
constexpr int32_t BOUNDARY_LOOP_START = 1000;
constexpr int32_t BOUNDARY_LOOP_END = 1100;
constexpr int32_t BOUNDARY_RANGE_END = 6000;
constexpr int32_t LOOP_STEP_SIZE = 100;
constexpr int32_t THERMAL_LOOP_BOUND = 10;

// Combined sequence constants
constexpr uint8_t COMBINED_SEQ_MIN_LENGTH = 5;
constexpr uint8_t COMBINED_SEQ_MOD = 20;
constexpr uint8_t COMBINED_OP_MOD = 12;

// Error test constants
constexpr int32_t ERROR_TEST_VALUE_NEG = -999;
constexpr int32_t ERROR_TEST_VALUE_POS = 99999;

// String length boundary values (G.CNS.02)
constexpr size_t STRING_LEN_SINGLE = 1;
constexpr size_t STRING_LEN_255 = 255;
constexpr size_t STRING_LEN_256 = 256;
constexpr size_t STRING_LEN_1023 = 1023;
constexpr size_t STRING_LEN_1024 = 1024;
constexpr size_t STRING_LEN_4095 = 4095;
constexpr size_t STRING_LEN_4096 = 4096;

// Boundary test values (G.CNS.02)
constexpr int32_t BOUNDARY_VALUE_999 = 999;
constexpr int32_t BOUNDARY_VALUE_5900 = 5900;
constexpr int32_t BOUNDARY_VALUE_6000 = 6000;
constexpr int32_t NEAR_INT32_MAX_NEG = -2147483647;

// Toggle and modulo constants (G.CNS.02)
constexpr int32_t TOGGLE_MOD = 2;
constexpr int32_t TOGGLE_EVEN = 0;
constexpr int32_t RESET_INTERVAL = 10;
constexpr int32_t RESET_INDEX = 9;
constexpr int32_t TRANSITION_MOD = 8;
constexpr int32_t NUM_TRANSITIONS_MOD = 30;
constexpr int32_t NUM_TRANSITIONS_BASE = 10;
constexpr int32_t MODE_INDEX_MOD = 4;
constexpr int32_t RACE_MODE_INDEX_MOD = 3;
constexpr int32_t RACE_LIMIT_MOD = 5;
constexpr int32_t THERMAL_OFFSET = 5;
constexpr int32_t THERMAL_INCREMENT = 1;

// Config test values (G.CNS.02)
constexpr int64_t CONFIG_VALUE_SMALL = 100;
constexpr int64_t CONFIG_VALUE_LARGE = 1000;
constexpr int64_t CONFIG_RACE_MULTIPLIER = 100;
constexpr int64_t RES_CONFIG_GPU = 2000;
constexpr int64_t RES_CONFIG_DDR = 3000;
constexpr int64_t RES_CONFIG_NPU = 4000;

// Combined operation type constants (G.CNS.02)
constexpr uint8_t COMBINED_OP_PERF_REQUEST = 0;
constexpr uint8_t COMBINED_OP_PERF_REQUEST_EX = 1;
constexpr uint8_t COMBINED_OP_POWER_LIMIT_BOOST = 2;
constexpr uint8_t COMBINED_OP_THERMAL_LIMIT_BOOST = 3;
constexpr uint8_t COMBINED_OP_LIMIT_REQUEST = 4;
constexpr uint8_t COMBINED_OP_SET_REQUEST_STATUS = 5;
constexpr uint8_t COMBINED_OP_SET_THERMAL_LEVEL = 6;
constexpr uint8_t COMBINED_OP_REQUEST_DEVICE_MODE = 7;
constexpr uint8_t COMBINED_OP_REQUEST_CMD_ID_COUNT = 8;
constexpr uint8_t COMBINED_OP_RESET_CLIENT = 9;
constexpr uint8_t COMBINED_OP_IS_VALID_RES_ID = 10;
constexpr uint8_t COMBINED_OP_IS_GOV_RES_ID = 11;

// State transition type constants (G.CNS.02)
constexpr uint8_t TRANSITION_ENABLE_STATUS = 0;
constexpr uint8_t TRANSITION_DISABLE_STATUS = 1;
constexpr uint8_t TRANSITION_THERMAL_INC = 2;
constexpr uint8_t TRANSITION_THERMAL_DEC = 3;
constexpr uint8_t TRANSITION_POWER_BOOST = 4;
constexpr uint8_t TRANSITION_THERMAL_BOOST = 5;
constexpr uint8_t TRANSITION_DEVICE_MODE = 6;
constexpr uint8_t TRANSITION_PERF_REQUEST = 7;

// ============================================================================
// Inline Validation Functions
// ============================================================================

inline bool CheckSize(size_t size, size_t minSize) {
    return size >= minSize;
}

inline bool CheckPointer(const void* ptr) {
    return ptr != nullptr;
}

inline bool CheckOffset(size_t offset, size_t size, size_t typeSize) {
    return offset + typeSize <= size;
}

// ============================================================================
// DataExtractor Class
// ============================================================================

class DataExtractor {
   public:
    explicit DataExtractor(const uint8_t* data, size_t size)
        : data_(data), size_(size), offset_(0) {
    }

    ~DataExtractor() = default;

    uint8_t ExtractUInt8() {
        const uint8_t* ptr = SafeRead(sizeof(uint8_t));
        if (ptr == nullptr) {
            return 0;
        }
        return *ptr;
    }

    int8_t ExtractInt8() {
        const uint8_t* ptr = SafeRead(sizeof(int8_t));
        if (ptr == nullptr) {
            return 0;
        }
        int8_t value = 0;
        (void)memcpy_s(&value, sizeof(int8_t), ptr, sizeof(int8_t));
        return value;
    }

    uint16_t ExtractUInt16() {
        const uint8_t* ptr = SafeRead(sizeof(uint16_t));
        if (ptr == nullptr) {
            return 0;
        }
        uint16_t value = 0;
        (void)memcpy_s(&value, sizeof(uint16_t), ptr, sizeof(uint16_t));
        return value;
    }

    int16_t ExtractInt16() {
        const uint8_t* ptr = SafeRead(sizeof(int16_t));
        if (ptr == nullptr) {
            return 0;
        }
        int16_t value = 0;
        (void)memcpy_s(&value, sizeof(int16_t), ptr, sizeof(int16_t));
        return value;
    }

    int32_t ExtractInt32() {
        const uint8_t* ptr = SafeRead(sizeof(int32_t));
        if (ptr == nullptr) {
            return 0;
        }
        int32_t value = 0;
        (void)memcpy_s(&value, sizeof(int32_t), ptr, sizeof(int32_t));
        return value;
    }

    uint32_t ExtractUInt32() {
        const uint8_t* ptr = SafeRead(sizeof(uint32_t));
        if (ptr == nullptr) {
            return 0;
        }
        uint32_t value = 0;
        (void)memcpy_s(&value, sizeof(uint32_t), ptr, sizeof(uint32_t));
        return value;
    }

    int64_t ExtractInt64() {
        const uint8_t* ptr = SafeRead(sizeof(int64_t));
        if (ptr == nullptr) {
            return 0;
        }
        int64_t value = 0;
        (void)memcpy_s(&value, sizeof(int64_t), ptr, sizeof(int64_t));
        return value;
    }

    uint64_t ExtractUInt64() {
        const uint8_t* ptr = SafeRead(sizeof(uint64_t));
        if (ptr == nullptr) {
            return 0;
        }
        uint64_t value = 0;
        (void)memcpy_s(&value, sizeof(uint64_t), ptr, sizeof(uint64_t));
        return value;
    }

    bool ExtractBool() {
        const uint8_t* ptr = SafeRead(sizeof(uint8_t));
        if (ptr == nullptr) {
            return false;
        }
        return *ptr != 0;
    }

    float ExtractFloat() {
        const uint8_t* ptr = SafeRead(sizeof(float));
        if (ptr == nullptr) {
            return 0.0f;
        }
        float value = 0.0f;
        if (memcpy_s(&value, sizeof(float), ptr, sizeof(float)) != 0) {
            return 0.0f;
        }
        return value;
    }

    std::string ExtractString(size_t maxLen = DEFAULT_STRING_LENGTH) {
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

    std::string ExtractStringWithLen(size_t len, size_t maxLen = DEFAULT_STRING_LENGTH) {
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

    std::vector<int32_t> ExtractInt32Vector(size_t maxElements = DEFAULT_VECTOR_SIZE) {
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

    std::vector<int64_t> ExtractInt64Vector(size_t maxElements = DEFAULT_VECTOR_SIZE) {
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

    std::vector<std::string> ExtractStringVector(size_t maxStrings = 5, size_t maxLen = 100) {
        std::vector<std::string> result;
        if (maxStrings == 0) {
            return result;
        }
        for (size_t i = 0; i < maxStrings && HasMore(); ++i) {
            result.push_back(ExtractString(maxLen));
        }
        return result;
    }

    bool HasMore() const {
        return offset_ < size_;
    }

    size_t Remaining() const {
        return size_ - offset_;
    }

    void Reset() {
        offset_ = 0;
    }

    size_t GetOffset() const {
        return offset_;
    }

    size_t GetSize() const {
        return size_;
    }

    DataExtractor(const DataExtractor&) = delete;
    DataExtractor& operator=(const DataExtractor&) = delete;
    DataExtractor(DataExtractor&&) = delete;
    DataExtractor& operator=(DataExtractor&&) = delete;

   private:
    bool CanExtract(size_t size) const {
        return offset_ + size <= size_;
    }

    const uint8_t* SafeRead(size_t size) {
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

}  // namespace FuzzUtils

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

bool InitializeSystem() {
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

SocPerfClient& GetSocPerfClient() {
    return SocPerfClient::GetInstance();
}

// ============================================================================
// Test Case Implementations
// ============================================================================

void TestCaseInit(DataExtractor& extractor) {
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

void TestCasePerfRequest(DataExtractor& extractor) {
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
    client.PerfRequest(cmdId, std::string(STRING_LEN_XLARGE, 'x'));
    client.PerfRequest(cmdId, std::string(STRING_LEN_XXLARGE, 'y'));

    for (int32_t i = 0; i < RAPID_CALL_COUNT; i++) {
        client.PerfRequest(cmdId + i, "rapid");
    }
}

void TestCasePerfRequestEx(DataExtractor& extractor) {
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
        client.PerfRequestEx(cmdId, i % TOGGLE_MOD == TOGGLE_EVEN, "toggle");
    }
}

void TestCasePowerLimitBoost(DataExtractor& extractor) {
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
        client.PowerLimitBoost(i % TOGGLE_MOD == TOGGLE_EVEN, "stress_toggle");
    }

    client.PowerLimitBoost(onOffTag, "");
    client.PowerLimitBoost(onOffTag, "short");
    client.PowerLimitBoost(onOffTag, std::string(STRING_LEN_XXLARGE, 'p'));
    client.PowerLimitBoost(onOffTag, std::string(STRING_LEN_XLARGE, 'P'));
}

void TestCaseThermalLimitBoost(DataExtractor& extractor) {
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
        client.ThermalLimitBoost(i % TOGGLE_MOD == TOGGLE_EVEN, "thermal_stress_toggle");
    }

    client.ThermalLimitBoost(onOffTag, "");
    client.ThermalLimitBoost(onOffTag, "short_thermal");
    client.ThermalLimitBoost(onOffTag, std::string(STRING_LEN_XXLARGE, 't'));
}

void TestCaseLimitRequest(DataExtractor& extractor) {
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

    std::vector<int32_t> singleTag = {1};
    std::vector<int64_t> singleConfig = {100};
    client.LimitRequest(clientId, singleTag, singleConfig, "single_element");

    std::vector<int32_t> moreTags = {1, 2, 3};
    std::vector<int64_t> fewerConfigs = {CONFIG_VALUE_SMALL};
    client.LimitRequest(clientId, moreTags, fewerConfigs, "mismatched");

    std::vector<int32_t> largeTags(MAX_VECTOR_SIZE, 1);
    std::vector<int64_t> largeConfigs(MAX_VECTOR_SIZE, CONFIG_VALUE_LARGE);
    client.LimitRequest(clientId, largeTags, largeConfigs, "large_arrays");

    std::vector<int32_t> resTags = {RES_ID_CPU, RES_ID_GPU, RES_ID_DDR, RES_ID_NPU};
    std::vector<int64_t> resConfigs = {CONFIG_VALUE_LARGE, RES_CONFIG_GPU, RES_CONFIG_DDR, RES_CONFIG_NPU};
    client.LimitRequest(clientId, resTags, resConfigs, "resource_tags");
}

void TestCaseSetRequestStatus(DataExtractor& extractor) {
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
        client.SetRequestStatus(i % TOGGLE_MOD == TOGGLE_EVEN, "rapid_toggle");
    }

    client.SetRequestStatus(status, "");
    client.SetRequestStatus(status, "short");
    client.SetRequestStatus(status, std::string(STRING_LEN_XXLARGE, 's'));
}

void TestCaseSetThermalLevel(DataExtractor& extractor) {
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

    for (int32_t i = 0; i <= THERMAL_LOOP_BOUND; i++) {
        client.SetThermalLevel(i);
    }
    for (int32_t i = THERMAL_LOOP_BOUND; i >= -THERMAL_LOOP_BOUND; i--) {
        client.SetThermalLevel(i);
    }
}

void TestCaseRequestDeviceMode(DataExtractor& extractor) {
    SocPerfClient& client = GetSocPerfClient();

    std::string mode = extractor.ExtractString(STRING_LEN_MEDIUM);
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

    client.RequestDeviceMode(std::string(STRING_LEN_LARGE, 'm'), status);
    client.RequestDeviceMode(std::string(STRING_LEN_XLARGE, 'M'), status);

    client.RequestDeviceMode("mode_with_underscore", status);
    client.RequestDeviceMode("mode-with-dash", status);
    client.RequestDeviceMode("mode.with.dot", status);
    client.RequestDeviceMode("mode@with@at", status);

    std::string modes[] = {"game", "video", "camera", "performance"};
    for (int32_t i = 0; i < STRESS_ITERATIONS; i++) {
        client.RequestDeviceMode(modes[i % MODE_INDEX_MOD], i % TOGGLE_MOD == TOGGLE_EVEN);
    }
}

void TestCaseRequestCmdIdCount(DataExtractor& extractor) {
    SocPerfClient& client = GetSocPerfClient();

    std::string msg = extractor.ExtractString(DEFAULT_STRING_LENGTH);

    std::string result = client.RequestCmdIdCount(msg);
    g_callCounter++;

    result = client.RequestCmdIdCount("");
    result = client.RequestCmdIdCount("test");
    result = client.RequestCmdIdCount("query");
    result = client.RequestCmdIdCount("statistics");
    result = client.RequestCmdIdCount(std::string(STRING_LEN_XXLARGE, 'c'));

    client.PerfRequest(TEST_CMD_ID_BASE, "generate_count");
    client.PerfRequest(TEST_CMD_ID_BASE + THERMAL_INCREMENT, "generate_count_2");
    client.PerfRequest(TEST_CMD_ID_BASE + THERMAL_OFFSET, "generate_count_3");
    result = client.RequestCmdIdCount("after_state_change");
}

void TestCaseResetClient(DataExtractor& extractor) {
    (void)extractor;
    SocPerfClient& client = GetSocPerfClient();

    client.ResetClient();
    g_callCounter++;

    client.PerfRequest(TEST_CMD_ID_BASE, "after_reset_1");
    client.SetThermalLevel(THERMAL_LEVEL_NORMAL);
    client.PowerLimitBoost(true, "boost_after_reset");

    client.ResetClient();

    client.PerfRequest(TEST_CMD_ID_BASE + THERMAL_INCREMENT, "after_second_reset");
    client.SetThermalLevel(THERMAL_LEVEL_WARNING);

    for (int32_t i = 0; i < THERMAL_LOOP_BOUND; i++) {
        client.ResetClient();
        client.PerfRequest(TEST_CMD_ID_BASE + i, "rapid_reset");
    }
}

void TestCaseConfigIsValidResId(DataExtractor& extractor) {
    auto& config = SocPerfConfig::GetInstance();

    int32_t resId = extractor.ExtractInt32();
    volatile bool result = config.IsValidResId(resId);
    (void)result;
    g_callCounter++;

    config.IsValidResId(0);
    config.IsValidResId(1);
    config.IsValidResId(-1);
    config.IsValidResId(BOUNDARY_VALUE_999);
    config.IsValidResId(FUZZ_MIN_RESOURCE_ID);
    config.IsValidResId(FUZZ_MAX_RESOURCE_ID);
    config.IsValidResId(BOUNDARY_VALUE_6000);
    config.IsValidResId(INT32_MAX);
    config.IsValidResId(INT32_MIN);

    for (int32_t i = BOUNDARY_LOOP_START; i <= BOUNDARY_LOOP_END; i++) {
        config.IsValidResId(i);
    }
    for (int32_t i = BOUNDARY_VALUE_5900; i <= BOUNDARY_RANGE_END; i++) {
        config.IsValidResId(i);
    }
}

void TestCaseConfigIsGovResId(DataExtractor& extractor) {
    auto& config = SocPerfConfig::GetInstance();

    int32_t resId = extractor.ExtractInt32();
    volatile bool result = config.IsGovResId(resId);
    (void)result;
    g_callCounter++;

    config.IsGovResId(0);
    config.IsGovResId(1);
    config.IsGovResId(-1);
    config.IsGovResId(BOUNDARY_VALUE_999);
    config.IsGovResId(FUZZ_MIN_RESOURCE_ID);
    config.IsGovResId(FUZZ_MAX_RESOURCE_ID);
    config.IsGovResId(BOUNDARY_VALUE_6000);
    config.IsGovResId(INT32_MAX);
    config.IsGovResId(INT32_MIN);

    for (int32_t i = 0; i <= FUZZ_MAX_RESOURCE_ID; i += LOOP_STEP_SIZE) {
        config.IsGovResId(i);
    }
}

// Helper function to handle combined sequence operations (reduces complexity)
void HandleCombinedSequenceOp(SocPerfClient& client, uint8_t op, DataExtractor& extractor) {
    switch (op) {
        case COMBINED_OP_PERF_REQUEST:
            client.PerfRequest(extractor.ExtractInt32(), extractor.ExtractString(STRING_LEN_MEDIUM));
            break;
        case COMBINED_OP_PERF_REQUEST_EX:
            client.PerfRequestEx(extractor.ExtractInt32(),
                                 extractor.ExtractBool(), extractor.ExtractString(STRING_LEN_MEDIUM));
            break;
        case COMBINED_OP_POWER_LIMIT_BOOST:
            client.PowerLimitBoost(extractor.ExtractBool(), extractor.ExtractString(STRING_LEN_MEDIUM));
            break;
        case COMBINED_OP_THERMAL_LIMIT_BOOST:
            client.ThermalLimitBoost(extractor.ExtractBool(), extractor.ExtractString(STRING_LEN_MEDIUM));
            break;
        case COMBINED_OP_LIMIT_REQUEST:
            client.LimitRequest(extractor.ExtractInt32(),
                                extractor.ExtractInt32Vector(DEFAULT_VECTOR_SIZE),
                                extractor.ExtractInt64Vector(DEFAULT_VECTOR_SIZE),
                                extractor.ExtractString(STRING_LEN_MEDIUM));
            break;
        case COMBINED_OP_SET_REQUEST_STATUS:
            client.SetRequestStatus(extractor.ExtractBool(), extractor.ExtractString(STRING_LEN_MEDIUM));
            break;
        case COMBINED_OP_SET_THERMAL_LEVEL:
            client.SetThermalLevel(extractor.ExtractInt32());
            break;
        case COMBINED_OP_REQUEST_DEVICE_MODE:
            client.RequestDeviceMode(extractor.ExtractString(STRING_LEN_SMALL), extractor.ExtractBool());
            break;
        case COMBINED_OP_REQUEST_CMD_ID_COUNT:
            client.RequestCmdIdCount(extractor.ExtractString(STRING_LEN_MEDIUM));
            break;
        case COMBINED_OP_RESET_CLIENT:
            client.ResetClient();
            break;
        case COMBINED_OP_IS_VALID_RES_ID:
            SocPerfConfig::GetInstance().IsValidResId(extractor.ExtractInt32());
            break;
        case COMBINED_OP_IS_GOV_RES_ID:
            SocPerfConfig::GetInstance().IsGovResId(extractor.ExtractInt32());
            break;
        default:
            break;
    }
}

void TestCaseCombinedSequence(DataExtractor& extractor) {
    SocPerfClient& client = GetSocPerfClient();

    uint8_t sequenceLength = extractor.ExtractUInt8() % COMBINED_SEQ_MOD + COMBINED_SEQ_MIN_LENGTH;

    for (uint8_t i = 0; i < sequenceLength && extractor.HasMore(); i++) {
        uint8_t op = extractor.ExtractUInt8() % COMBINED_OP_MOD;
        HandleCombinedSequenceOp(client, op, extractor);
        g_callCounter++;
    }
}

void TestCaseBoundaryValues(DataExtractor& extractor) {
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
    client.SetThermalLevel(NEAR_INT32_MAX_NEG);
    client.SetThermalLevel(INT32_MAX);

    client.PerfRequest(1, "");
    client.PerfRequest(1, std::string(STRING_LEN_SINGLE, 'a'));
    client.PerfRequest(1, std::string(STRING_LEN_255, 'b'));
    client.PerfRequest(1, std::string(STRING_LEN_256, 'c'));
    client.PerfRequest(1, std::string(STRING_LEN_1023, 'd'));
    client.PerfRequest(1, std::string(STRING_LEN_1024, 'e'));
    client.PerfRequest(1, std::string(STRING_LEN_4095, 'f'));
    client.PerfRequest(1, std::string(STRING_LEN_4096, 'g'));

    std::vector<int32_t> emptyTags;
    std::vector<int64_t> emptyConfigs;
    client.LimitRequest(0, emptyTags, emptyConfigs, "empty");

    std::vector<int32_t> singleTag = {0};
    std::vector<int64_t> singleConfig = {0};
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

void TestCaseRaceSimulation(DataExtractor& extractor) {
    (void)extractor;
    SocPerfClient& client = GetSocPerfClient();

    for (int32_t i = 0; i < STRESS_ITERATIONS; i++) {
        client.SetRequestStatus(true, "race_enable");
        client.SetRequestStatus(false, "race_disable");

        client.PowerLimitBoost(true, "race_power_on");
        client.PowerLimitBoost(false, "race_power_off");
        client.ThermalLimitBoost(true, "race_thermal_on");
        client.ThermalLimitBoost(false, "race_thermal_off");

        client.SetThermalLevel(i % THERMAL_LOOP_BOUND);

        std::string modes[] = {"game", "video", "camera"};
        client.RequestDeviceMode(modes[i % RACE_MODE_INDEX_MOD], true);
        client.RequestDeviceMode(modes[i % RACE_MODE_INDEX_MOD], false);

        client.PerfRequest(i, "race_request");
        client.PerfRequestEx(i, true, "race_ex_on");
        client.PerfRequestEx(i, false, "race_ex_off");

        g_callCounter++;
    }

    for (int32_t i = 0; i < STRESS_LOOP_MEDIUM; i++) {
        std::vector<int32_t> tags = {BOUNDARY_LOOP_START + i};
        std::vector<int64_t> configs = {CONFIG_RACE_MULTIPLIER * i};
        client.LimitRequest(i % RACE_LIMIT_MOD, tags, configs, "race_limit");
    }
}

void TestCaseErrorPaths(DataExtractor& extractor) {
    SocPerfClient& client = GetSocPerfClient();

    client.ResetClient();

    client.PerfRequest(ERROR_TEST_VALUE_NEG, "after_reset");
    client.PerfRequestEx(ERROR_TEST_VALUE_NEG, true, "after_reset_ex");
    client.LimitRequest(-1, {}, {}, "after_reset_limit");
    client.SetThermalLevel(ERROR_TEST_VALUE_NEG);

    client.SetRequestStatus(false, "disable_for_error_test");
    client.PerfRequest(1, "should_be_blocked");
    client.PerfRequestEx(1, true, "should_be_blocked_ex");
    client.LimitRequest(1, {1}, {1}, "should_be_blocked_limit");

    client.SetRequestStatus(true, "re-enable");
    client.PerfRequest(1, "after_re-enable");

    client.SetThermalLevel(ERROR_TEST_VALUE_POS);
    client.SetThermalLevel(-ERROR_TEST_VALUE_POS);
    client.SetThermalLevel(0);

    client.RequestCmdIdCount("before");
    client.PerfRequest(1, "between");
    client.RequestCmdIdCount("after");

    for (int32_t i = 0; i < THERMAL_LOOP_BOUND; i++) {
        client.SetRequestStatus(i % TOGGLE_MOD == TOGGLE_EVEN, "rapid_status");
        client.PerfRequest(i, "during_status_change");
    }

    g_callCounter++;
}

void TestStringArrayFuzzing(SocPerfClient& client, int32_t cmdId, DataExtractor& extractor) {
    std::vector<std::string> testStrings = {
        extractor.ExtractString(STRING_LEN_SMALL),
        extractor.ExtractString(STRING_LEN_MEDIUM),
        extractor.ExtractString(STRING_LEN_LARGE),
        extractor.ExtractString(STRING_LEN_XLARGE),
        extractor.ExtractString(STRING_LEN_XXLARGE),
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

        std::vector<int32_t> tags = {1};
        std::vector<int64_t> configs = {100};
        client.LimitRequest(0, tags, configs, str);

        g_callCounter++;
    }
}

void TestPatternArrayFuzzing(SocPerfClient& client, int32_t cmdId) {
    std::string patterns[] = {
        "",
        " ",
        "  ",
        "\t",
        "\n",
        "\r\n",
        "\0",
        "\x00\x01\x02",
        "Chinese test",
        "Japanese test",
        "Korean test",
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

void TestCaseStringFuzzing(DataExtractor& extractor) {
    SocPerfClient& client = GetSocPerfClient();
    int32_t cmdId = extractor.ExtractInt32();
    TestStringArrayFuzzing(client, cmdId, extractor);
    TestPatternArrayFuzzing(client, cmdId);
}

void TestCaseVectorFuzzing(DataExtractor& extractor) {
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

    std::string msg = extractor.ExtractString(STRING_LEN_LARGE);
    int32_t clientId = extractor.ExtractInt32();

    client.LimitRequest(clientId, tags, configs, msg);
    g_callCounter++;

    std::vector<int32_t> sizes[] = {
        {},
        {1},
        {1, 2},
        {1, 2, 3, 4, 5},
        {1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
    };

    for (const auto& sizeVec : sizes) {
        std::vector<int64_t> configVec(sizeVec.size(), CONFIG_VALUE_SMALL);
        client.LimitRequest(clientId, sizeVec, configVec, "size_test");
        g_callCounter++;
    }

    std::vector<int32_t> extremeTags = {
        0, 1, -1, INT32_MAX, INT32_MIN,
        1000, 2000, 3000, 4000, 5000, 5999};
    std::vector<int64_t> extremeConfigs = {
        0, 1, -1, INT64_MAX, INT64_MIN,
        100, 200, 300, 400, 500,
        0x7FFFFFFFFFFFFFFF, 0x8000000000000000};

    client.LimitRequest(clientId, extremeTags, extremeConfigs, "extreme_values");
    g_callCounter++;
}

// Helper function to handle state machine transition
void HandleStateTransition(SocPerfClient& client, uint8_t transition, uint8_t i) {
    switch (transition) {
        case TRANSITION_ENABLE_STATUS:
            client.SetRequestStatus(true, "transition_enable");
            break;
        case TRANSITION_DISABLE_STATUS:
            client.SetRequestStatus(false, "transition_disable");
            break;
        case TRANSITION_THERMAL_INC:
            client.SetThermalLevel((i % THERMAL_LOOP_BOUND) + THERMAL_INCREMENT);
            break;
        case TRANSITION_THERMAL_DEC:
            client.SetThermalLevel(std::max(0, (i % THERMAL_LOOP_BOUND) - THERMAL_OFFSET));
            break;
        case TRANSITION_POWER_BOOST:
            client.PowerLimitBoost(i % TOGGLE_MOD == TOGGLE_EVEN, "transition_power");
            break;
        case TRANSITION_THERMAL_BOOST:
            client.ThermalLimitBoost(i % TOGGLE_MOD == TOGGLE_EVEN, "transition_thermal");
            break;
        case TRANSITION_DEVICE_MODE: {
            std::string modes[] = {"game", "video", "camera", "normal"};
            client.RequestDeviceMode(modes[i % MODE_INDEX_MOD], i % TOGGLE_MOD == TOGGLE_EVEN);
            break;
        }
        case TRANSITION_PERF_REQUEST:
            client.PerfRequest(TEST_CMD_ID_BASE + i, "transition_request");
            break;
        default:
            break;
    }
}

void TestCaseStateMachine(DataExtractor& extractor) {
    SocPerfClient& client = GetSocPerfClient();

    bool initialStatus = extractor.ExtractBool();
    int32_t initialLevel = extractor.ExtractInt32() % THERMAL_LOOP_BOUND;

    client.SetRequestStatus(initialStatus, "initial_state");
    client.SetThermalLevel(initialLevel);

    uint8_t numTransitions = extractor.ExtractUInt8() % NUM_TRANSITIONS_MOD + NUM_TRANSITIONS_BASE;

    for (uint8_t i = 0; i < numTransitions && extractor.HasMore(); i++) {
        uint8_t transition = extractor.ExtractUInt8() % TRANSITION_MOD;
        HandleStateTransition(client, transition, i);

        if (i % RESET_INTERVAL == RESET_INDEX) {
            client.ResetClient();
            client.SetRequestStatus(true, "reset_recovery");
        }

        g_callCounter++;
    }

    client.SetRequestStatus(true, "final_state");
    client.SetThermalLevel(0);
}

using IntegrationTestCaseFunc = void (*)(DataExtractor&);

static const IntegrationTestCaseFunc INTEGRATION_TEST_FUNCS[TEST_CASE_COUNT] = {
    TestCaseInit,
    TestCasePerfRequest,
    TestCasePerfRequestEx,
    TestCasePowerLimitBoost,
    TestCaseThermalLimitBoost,
    TestCaseLimitRequest,
    TestCaseSetRequestStatus,
    TestCaseSetThermalLevel,
    TestCaseRequestDeviceMode,
    TestCaseRequestCmdIdCount,
    TestCaseResetClient,
    TestCaseConfigIsValidResId,
    TestCaseConfigIsGovResId,
    TestCaseCombinedSequence,
    TestCaseBoundaryValues,
    TestCaseRaceSimulation,
    TestCaseErrorPaths,
    TestCaseStringFuzzing,
    TestCaseVectorFuzzing,
    TestCaseStateMachine,
};

// Helper function to dispatch test case
void DispatchTestCase(uint8_t testCase, DataExtractor& extractor) {
    if (testCase < TEST_CASE_COUNT) {
        INTEGRATION_TEST_FUNCS[testCase](extractor);
    }
}

// ============================================================================
// Main Fuzz Entry Point
// ============================================================================

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
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
    DispatchTestCase(testCase, extractor);

    return 0;
}
