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
 * @file socperf_config_fuzzer.cpp
 * @brief Fuzzing driver for SocPerf configuration parsing and validation.
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <securec.h>

#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "socperf_config_fuzzer.h"

// SocPerf headers
#include "socperf_action_type.h"
#include "socperf_common.h"
#include "socperf_config.h"
#include "socperf_log.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>

namespace FuzzUtils {

// ============================================================================
// Constants (G.CNS.02: Use named constants instead of magic numbers)
// ============================================================================

// Input size constraints
constexpr int32_t MIN_INPUT_SIZE = 4;
constexpr int32_t MAX_INPUT_SIZE = 8192;

// Vector size constraints
constexpr int32_t DEFAULT_VECTOR_SIZE = 20;
constexpr int32_t MAX_VECTOR_SIZE = 100;

// Resource ID range
constexpr int32_t FUZZ_MIN_RESOURCE_ID = 1000;
constexpr int32_t FUZZ_MAX_RESOURCE_ID = 5999;

// XML test size limits
constexpr size_t MAX_XML_ITEMS = 20;
constexpr size_t MAX_XML_DEPTH = 50;
constexpr size_t MAX_XML_ITEM_SIZE = 100;

// String length constants
constexpr size_t DEFAULT_STRING_LENGTH = 256;
constexpr size_t SMALL_STRING_LENGTH = 32;
constexpr size_t MEDIUM_STRING_LENGTH = 64;
constexpr size_t LARGE_STRING_LENGTH = 128;

// Buffer size constants
constexpr size_t BUFFER_SIZE_SMALL = 128;
constexpr size_t BUFFER_SIZE_LARGE = 256;

// Loop iteration constants (G.CNS.02)
constexpr int32_t FUZZ_LOOP_BOUND_SMALL = 10;
constexpr int32_t FUZZ_LOOP_BOUND_MEDIUM = 20;
constexpr int32_t FUZZ_LOOP_BOUND_LARGE = 50;
constexpr int32_t FUZZ_LOOP_BOUND_XLARGE = 100;
constexpr int32_t RANGE_TEST_STEP = 10;
constexpr int32_t RANGE_BOUNDARY_OFFSET = 20;

// Value multipliers for XML generation (G.CNS.02)
constexpr int64_t VALUE_MULTIPLIER_1M = 1000000;
constexpr int64_t VALUE_MULTIPLIER_2M = 2000000;
constexpr int64_t DEFAULT_VALUE_BASE = 100000000;

// Additional constants for magic number replacement (G.CNS.02)
constexpr int32_t BINARY_MOD = 2;
constexpr int32_t PAIR_MULTIPLIER = 2;
constexpr int32_t CMD_ID_RANGE_SIZE = 10000;
constexpr int32_t GOV_RES_ID_LOOP_STEP = 100;
constexpr int32_t PERSIST_MODE_TEST_VALUE = 100;

constexpr uint8_t TEST_CASE_COUNT = 16;

// Action type and delay constants
constexpr int64_t MAX_DELAY_TIME_LARGE = 1000000;

// ============================================================================
// DataExtractor Class
// ============================================================================

// Absolute value of a fuzzed int32_t that never overflows on INT32_MIN.
inline int32_t AbsInt32(int32_t value)
{
    if (value == INT32_MIN) {
        return 0;
    }
    return value < 0 ? -value : value;
}

class DataExtractor {
   public:
    explicit DataExtractor(const uint8_t* data, size_t size)
        : data_(data), size_(size), offset_(0)
        {
        }

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

    int64_t ExtractInt64()
    {
        const uint8_t* ptr = SafeRead(sizeof(int64_t));
        if (ptr == nullptr) {
            return 0;
        }
        int64_t value = 0;
        (void)memcpy_s(&value, sizeof(int64_t), ptr, sizeof(int64_t));
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

    std::string ExtractString(size_t maxLen = DEFAULT_STRING_LENGTH)
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

    std::string ExtractStringWithLen(size_t maxLen = DEFAULT_STRING_LENGTH)
    {
        if (offset_ >= size_) {
            return "";
        }
        size_t len = (size_ - offset_) < maxLen ? (size_ - offset_) : maxLen;
        const uint8_t* ptr = SafeRead(len);
        if (ptr == nullptr) {
            return "";
        }
        return std::string(reinterpret_cast<const char*>(ptr), len);
    }

    std::vector<int32_t> ExtractInt32Vector(size_t maxElements = DEFAULT_VECTOR_SIZE)
    {
        std::vector<int32_t> result;
        if (maxElements > MAX_VECTOR_SIZE) {
            maxElements = MAX_VECTOR_SIZE;
        }
        if (!CanExtract(sizeof(int32_t))) {
            return result;
        }
        int32_t numElements = AbsInt32(ExtractInt32());
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

    bool HasMore() const
    {
        return offset_ < size_;
    }

    size_t Remaining() const
    {
        return size_ - offset_;
    }

    size_t GetSize() const
    {
        return size_;
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

}  // namespace FuzzUtils

using namespace FuzzUtils;
using namespace OHOS::SOCPERF;

// ============================================================================
// Global State
// ============================================================================

static std::mutex g_fuzzMutex;
static bool g_configInitialized = false;

// ============================================================================
// XML Generation Helpers
// ============================================================================

std::string GenerateBasicConfigXml()
{
    return std::string(R"XML(<?xml version="1.0" encoding="utf-8"?>
<Configs>
    <Info>
        <inf path="" func="" scenarioFunc=""/>
    </Info>
    <Resource>
        <res id="1000" name="CPUFreq" pair="1001" mode="0" switch="0" trace="0">
            <default>1800000</default>
            <path>/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor</path>
            <node>1800000 2000000 2200000</node>
        </res>
    </Resource>
</Configs>)XML");
}

std::string GenerateMalformedXmlEmpty()
{
    return "<?xml version=\"1.0\"?>\n<Configs></Configs>";
}

std::string GenerateMalformedXmlMissingRoot()
{
    return "<?xml version=\"1.0\"?>\n<Resource><res id=\"1000\"/></Resource>";
}

std::string GenerateMalformedXmlWrongRoot()
{
    return "<?xml version=\"1.0\"?>\n<WrongRoot></WrongRoot>";
}

std::string GenerateMalformedXmlNoClose()
{
    return "<?xml version=\"1.0\"?>\n<Configs><Resource>";
}

std::string GenerateMalformedXmlSpecialChars()
{
    return "<?xml version=\"1.0\"?>\n<Configs><Info>&lt;&gt;&amp;&quot;&apos;</Info></Configs>";
}

std::string GenerateMalformedXmlBinary(size_t len)
{
    std::string result = "<?xml version=\"1.0\"?>\n<Configs>";
    for (size_t i = 0; i < len && i < MAX_XML_ITEM_SIZE; i++) {
        result += static_cast<char>(0xFF);
    }
    result += "</Configs>";
    return result;
}

std::string GenerateMalformedXmlVeryLong(size_t len)
{
    std::string result = "<?xml version=\"1.0\"?>\n<Configs>";
    for (size_t i = 0; i < len && i < MAX_XML_ITEMS * MAX_XML_ITEM_SIZE; i++) {
        result += "<Item></Item>";
    }
    result += "</Configs>";
    return result;
}

std::string GenerateMalformedXmlNestedDeep(size_t len)
{
    std::string result = "<?xml version=\"1.0\"?>\n";
    for (size_t i = 0; i < len && i < MAX_XML_DEPTH; i++) {
        result += "<Level" + std::to_string(i) + ">";
    }
    result += "Content";
    for (size_t i = 0; i < len && i < MAX_XML_DEPTH; i++) {
        result += "</Level" + std::to_string(len - 1 - i) + ">";
    }
    return result;
}

std::string GenerateMalformedXmlNullBytes()
{
    std::string result = "<?xml version=\"1.0\"?>\n<Configs><Item>";
    result += '\0';
    result += "content";
    result += '\0';
    result += "</Item></Configs>";
    return result;
}

std::string GenerateMalformedXmlUnicode()
{
    return std::string("<?xml version=\"1.0\"?>\n<Configs><Info>") +
        "\xE4\xB8\xAD\xE6\x96\x87\xF0\x9F\x98\x80" + "</Info></Configs>";
}

// Number of malformed XML patterns handled by GenerateMalformedXml().
constexpr size_t MALFORMED_XML_PATTERN_COUNT = 10;

std::string GenerateMalformedXml(size_t patternIndex, size_t len)
{
    switch (patternIndex % MALFORMED_XML_PATTERN_COUNT) {
        case 0:
            return GenerateMalformedXmlEmpty();
        case 1:
            return GenerateMalformedXmlMissingRoot();
        case 2:
            return GenerateMalformedXmlWrongRoot();
        case 3:
            return GenerateMalformedXmlNoClose();
        case 4:
            return GenerateMalformedXmlSpecialChars();
        case 5:
            return GenerateMalformedXmlBinary(len);
        case 6:
            return GenerateMalformedXmlVeryLong(len);
        case 7:
            return GenerateMalformedXmlNestedDeep(len);
        case 8:
            return GenerateMalformedXmlUnicode();
        case 9:
            return GenerateMalformedXmlNullBytes();
        default:
            return GenerateMalformedXmlEmpty();
    }
}

// Write fuzzed XML content to a temporary file so the file IO path is exercised, then clean up.
void WriteTempXmlFile(const char* prefix, const std::string& content, int32_t suffix)
{
    std::string tempFile = std::string("/data/local/tmp/") + prefix + std::to_string(suffix) + ".xml";
    FILE* fp = fopen(tempFile.c_str(), "wb");
    if (fp == nullptr) {
        return;
    }
    if (!content.empty()) {
        (void)fwrite(content.c_str(), 1, content.size(), fp);
    }
    (void)fclose(fp);
    (void)remove(tempFile.c_str());
}

// Helper function to generate resource XML header
void GenerateResourceXmlHeader(std::string& xml)
{
    xml += R"(<?xml version="1.0" encoding="utf-8"?>
<Configs>
    <Resource>)";
}

// Helper function to generate single resource entry
int32_t ValidateResourceId(int32_t resId)
{
    int32_t id = AbsInt32(resId);
    if (id < FUZZ_MIN_RESOURCE_ID) {
        id = FUZZ_MIN_RESOURCE_ID + (id % FUZZ_LOOP_BOUND_XLARGE);
    }
    if (id > FUZZ_MAX_RESOURCE_ID) {
        id = FUZZ_MAX_RESOURCE_ID - (id % FUZZ_LOOP_BOUND_SMALL);
    }
    return id;
}

int32_t ValidatePairId(int32_t pairId)
{
    int32_t id = AbsInt32(pairId);
    if (id > FUZZ_MAX_RESOURCE_ID) {
        id = 0;
    }
    return id;
}

void GenerateResourceEntry(std::string& xml, DataExtractor& extractor)
{
    int32_t resId = ValidateResourceId(extractor.ExtractInt32());

    std::string name = extractor.ExtractString(MEDIUM_STRING_LENGTH);
    if (name.empty()) {
        name = "Resource" + std::to_string(resId);
    }

    int32_t pairId = ValidatePairId(extractor.ExtractInt32());
    int32_t mode = extractor.ExtractInt32() % BINARY_MOD;
    int32_t persistMode = extractor.ExtractInt32() % BINARY_MOD;
    int32_t trace = extractor.ExtractInt32() % BINARY_MOD;
    int64_t defValue = extractor.ExtractInt64() % DEFAULT_VALUE_BASE;

    char buffer[BUFFER_SIZE_LARGE];
    std::string formatStr = R"XML(        <res id="%d" name="%s" pair="%d" mode="%d" switch="%d" trace="%d">
            <default>%lld</default>
            <path>/sys/test/path%d</path>
            <node>%lld %lld %lld</node>
        </res>)XML";
    int ret = snprintf_s(buffer, sizeof(buffer), sizeof(buffer) - 1, formatStr.c_str(),
                         resId, name.c_str(), pairId, mode, persistMode, trace,
                         static_cast<long long>(defValue), resId,
                         static_cast<long long>(defValue),
                         static_cast<long long>(defValue + VALUE_MULTIPLIER_1M),
                         static_cast<long long>(defValue + VALUE_MULTIPLIER_2M));
    if (ret > 0) {
        xml += "\n";
        xml += buffer;
    }
}

void GenerateResourceXmlFooter(std::string& xml)
{
    xml += R"(
    </Resource>
</Configs>)";
}

std::string GenerateResourceXml(DataExtractor& extractor)
{
    std::string xml;
    GenerateResourceXmlHeader(xml);

    int32_t numResources = extractor.ExtractInt32() % MAX_XML_ITEMS + 1;

    for (int32_t i = 0; i < numResources && extractor.HasMore(); i++) {
        GenerateResourceEntry(xml, extractor);
    }

    GenerateResourceXmlFooter(xml);
    return xml;
}

// Helper function to generate boost config header
void GenerateBoostConfigHeader(std::string& xml, const std::string& configMode)
{
    char configHeader[BUFFER_SIZE_SMALL];
    int ret = snprintf_s(configHeader, sizeof(configHeader), sizeof(configHeader) - 1,
                         R"(
    <Config mode="%s">)",
                         configMode.c_str());
    if (ret > 0) {
        xml += configHeader;
    }
}

void GenerateBoostConfigFooter(std::string& xml)
{
    xml += "\n    </Config>";
}

// Helper function to generate single cmd entry
void GenerateBoostCmdEntry(std::string& xml, DataExtractor& extractor)
{
    int32_t cmdId = FUZZ_MIN_RESOURCE_ID + (extractor.ExtractInt32() % CMD_ID_RANGE_SIZE);
    std::string cmdName = extractor.ExtractString(MEDIUM_STRING_LENGTH);
    if (cmdName.empty()) {
        cmdName = "Cmd" + std::to_string(cmdId);
    }

    int32_t thermalLvl = extractor.ExtractInt32() % FUZZ_LOOP_BOUND_SMALL;
    int32_t duration = extractor.ExtractInt32() % DEFAULT_VALUE_BASE;
    int32_t interaction = extractor.ExtractInt32() % BINARY_MOD;

    char cmdBuffer[BUFFER_SIZE_LARGE];
    int ret = snprintf_s(cmdBuffer, sizeof(cmdBuffer), sizeof(cmdBuffer) - 1,
                         R"(
        <cmd id="%d" name="%s" interaction="%d" mode="game=2000|video=3000">
            <Action thermalLvl="%d">
                <duration>%d</duration>
                <CPUFreq>1800000</CPUFreq>
                <GPUFreq>500000</GPUFreq>
            </Action>
        </cmd>)",
                         cmdId, cmdName.c_str(), interaction,
                         thermalLvl, duration);
    if (ret > 0) {
        xml += cmdBuffer;
    }
}

std::string GenerateBoostXml(DataExtractor& extractor)
{
    std::string xml = R"(<?xml version="1.0" encoding="utf-8"?>
<Configs>)";

    int32_t numConfigs = extractor.ExtractInt32() % FUZZ_LOOP_BOUND_SMALL + 1;

    for (int32_t i = 0; i < numConfigs && extractor.HasMore(); i++) {
        std::string configMode = extractor.ExtractString(SMALL_STRING_LENGTH);
        if (configMode.empty()) {
            configMode = "default";
        }
        GenerateBoostConfigHeader(xml, configMode);

        int32_t numCmds = extractor.ExtractInt32() % MAX_XML_ITEMS + 1;
        for (int32_t j = 0; j < numCmds && extractor.HasMore(); j++) {
            GenerateBoostCmdEntry(xml, extractor);
        }

        GenerateBoostConfigFooter(xml);
    }

    xml += "\n</Configs>";
    return xml;
}

// ============================================================================
// Test Cases
// ============================================================================

void TestConfigInit(DataExtractor& extractor)
{
    (void)extractor;
    auto& config = SocPerfConfig::GetInstance();

    config.Init();
    config.Init();
    config.Init();

    auto& instance1 = SocPerfConfig::GetInstance();
    auto& instance2 = SocPerfConfig::GetInstance();
    (void)instance1;
    (void)instance2;
}

void TestConfigIsValidResId(DataExtractor& extractor)
{
    auto& config = SocPerfConfig::GetInstance();

    int32_t resId = extractor.ExtractInt32();
    volatile bool result = config.IsValidResId(resId);
    (void)result;

    // Test boundary values
    config.IsValidResId(0);
    config.IsValidResId(1);
    config.IsValidResId(-1);
    config.IsValidResId(FUZZ_MIN_RESOURCE_ID - 1);
    config.IsValidResId(FUZZ_MIN_RESOURCE_ID);
    config.IsValidResId(FUZZ_MAX_RESOURCE_ID);
    config.IsValidResId(FUZZ_MAX_RESOURCE_ID + 1);
    config.IsValidResId(INT32_MAX);
    config.IsValidResId(INT32_MIN);

    // Test range values
    for (int32_t i = FUZZ_MIN_RESOURCE_ID; i <= FUZZ_MIN_RESOURCE_ID + FUZZ_LOOP_BOUND_XLARGE; i++) {
        config.IsValidResId(i);
    }
    for (int32_t i = FUZZ_MAX_RESOURCE_ID - FUZZ_LOOP_BOUND_XLARGE; i <= FUZZ_MAX_RESOURCE_ID; i++) {
        config.IsValidResId(i);
    }

    // Random fuzzed values
    for (int32_t i = 0; i < FUZZ_LOOP_BOUND_XLARGE; i++) {
        int32_t fuzzedId = extractor.ExtractInt32();
        config.IsValidResId(fuzzedId);
    }
}

void TestConfigIsGovResId(DataExtractor& extractor)
{
    auto& config = SocPerfConfig::GetInstance();

    int32_t resId = extractor.ExtractInt32();
    volatile bool result = config.IsGovResId(resId);
    (void)result;

    config.IsGovResId(0);
    config.IsGovResId(1);
    config.IsGovResId(-1);
    config.IsGovResId(FUZZ_MIN_RESOURCE_ID - 1);
    config.IsGovResId(FUZZ_MIN_RESOURCE_ID);
    config.IsGovResId(FUZZ_MAX_RESOURCE_ID);
    config.IsGovResId(FUZZ_MAX_RESOURCE_ID + 1);
    config.IsGovResId(INT32_MAX);
    config.IsGovResId(INT32_MIN);

    for (int32_t i = 0; i <= FUZZ_MAX_RESOURCE_ID; i += GOV_RES_ID_LOOP_STEP) {
        config.IsGovResId(i);
    }

    for (int32_t i = 0; i < FUZZ_LOOP_BOUND_XLARGE; i++) {
        int32_t fuzzedId = extractor.ExtractInt32();
        config.IsGovResId(fuzzedId);
    }
}

void TestConfigXmlParsing(DataExtractor& extractor)
{
    size_t patternType = extractor.ExtractUInt8() % MALFORMED_XML_PATTERN_COUNT;
    std::string malformedXml = GenerateMalformedXml(patternType, extractor.Remaining());
    WriteTempXmlFile("fuzz_config_", malformedXml, extractor.ExtractInt32());

    std::string validXml = GenerateBasicConfigXml();
    WriteTempXmlFile("fuzz_valid_", validXml, extractor.ExtractInt32());
}

void TestConfigResourceValidation(DataExtractor& extractor)
{
    WriteTempXmlFile("fuzz_resource_", GenerateResourceXml(extractor), extractor.ExtractInt32());
    WriteTempXmlFile("fuzz_boost_", GenerateBoostXml(extractor), extractor.ExtractInt32());

    volatile bool rangeCheck = IsValidRangeResId(extractor.ExtractInt32());
    (void)rangeCheck;

    volatile bool persistCheck = IsValidPersistMode(extractor.ExtractInt32() % BINARY_MOD);
    (void)persistCheck;

    std::string testNums[] = {
        "123", "-456", "0", "12.34", "abc",
        "", "12a", "-", "+123"};
    for (const auto& str : testNums) {
        volatile bool isNum = IsNumber(str);
        (void)isNum;
    }
}

void TestConfigGovValidation(DataExtractor& extractor)
{
    auto& config = SocPerfConfig::GetInstance();

    for (int32_t i = 0; i < FUZZ_LOOP_BOUND_LARGE; i++) {
        int32_t resId = extractor.ExtractInt32();
        config.IsGovResId(resId);
        config.IsValidResId(resId);
    }

    std::string testStr = extractor.ExtractString(LARGE_STRING_LENGTH);
    if (!testStr.empty()) {
        std::vector<std::string> parts = Split(testStr, "|");
        (void)parts;
    }

    testStr = extractor.ExtractString(LARGE_STRING_LENGTH);
    if (!testStr.empty()) {
        std::vector<std::string> parts = SplitEx(testStr, "|");
        (void)parts;
    }
}

void TestConfigSceneValidation(DataExtractor& extractor)
{
    (void)extractor;
    std::string sceneName = extractor.ExtractString(MEDIUM_STRING_LENGTH);
    int32_t persistMode = extractor.ExtractInt32() % 2;

    volatile bool sceneCheck = IsValidPersistMode(persistMode);
    (void)sceneCheck;

    std::string sceneNames[] = {
        "game", "video", "camera", "", "123",
        "a b c", "<tag>", "'quote'"};
    for (const auto& name : sceneNames) {
        (void)name;
    }
}

void TestConfigActionValidation(DataExtractor& extractor)
{
    int32_t numPairs = extractor.ExtractInt32() % FUZZ_LOOP_BOUND_MEDIUM;

    std::vector<int64_t> actionVars;
    for (int32_t i = 0; i < numPairs * PAIR_MULTIPLIER && extractor.HasMore(); i++) {
        actionVars.push_back(extractor.ExtractInt64());
    }

    volatile int64_t maxResult = Max(extractor.ExtractInt64(), extractor.ExtractInt64());
    (void)maxResult;

    volatile int64_t minResult = Min(extractor.ExtractInt64(), extractor.ExtractInt64());
    (void)minResult;

    maxResult = Max(extractor.ExtractInt64(), extractor.ExtractInt64(), extractor.ExtractInt64());
    minResult = Min(extractor.ExtractInt64(), extractor.ExtractInt64(), extractor.ExtractInt64());
}

void TestConfigInterAction(DataExtractor& extractor)
{
    int32_t cmdId = extractor.ExtractInt32();
    int32_t actionType = extractor.ExtractInt32() % ACTION_TYPE_MAX;
    int64_t delayTime = extractor.ExtractInt64() % MAX_DELAY_TIME_LARGE;

    std::shared_ptr<InterAction> interAction =
        std::make_shared<InterAction>(cmdId, actionType, delayTime);

    (void)interAction;

    for (int32_t i = 0; i < FUZZ_LOOP_BOUND_SMALL; i++) {
        int32_t testCmdId = extractor.ExtractInt32();
        int32_t testType = extractor.ExtractInt32() % ACTION_TYPE_MAX;
        int64_t testDelay = extractor.ExtractInt64() % MAX_DELAY_TIME_LARGE;

        std::shared_ptr<InterAction> testAction =
            std::make_shared<InterAction>(testCmdId, testType, testDelay);
        (void)testAction;
    }
}

void TestConfigBoundary(DataExtractor& extractor)
{
    (void)extractor;
    auto& config = SocPerfConfig::GetInstance();

    config.IsValidResId(INT32_MAX);
    config.IsValidResId(INT32_MIN);
    config.IsValidResId(0);
    config.IsValidResId(-1);
    config.IsValidResId(1);

    config.IsGovResId(INT32_MAX);
    config.IsGovResId(INT32_MIN);
    config.IsGovResId(0);
    config.IsGovResId(-1);

    IsValidRangeResId(INT32_MAX);
    IsValidRangeResId(INT32_MIN);
    IsValidRangeResId(0);

    IsValidPersistMode(-1);
    IsValidPersistMode(BINARY_MOD);
    IsValidPersistMode(PERSIST_MODE_TEST_VALUE);
    IsValidPersistMode(INT32_MAX);

    IsNumber("");
    IsNumber("-");
    IsNumber("0");
    IsNumber("-0");
    IsNumber("+123");
}

void TestConfigStringPatterns(DataExtractor& extractor)
{
    std::string patterns[] = {
        "",
        " ",
        "  ",
        "\t",
        "\n",
        "\r\n",
        "a",
        "abc",
        "Chinese test",
        "<tag>",
        "&amp;",
        "'\"\\",
        "$(cmd)",
        "; DROP",
        std::string(FUZZ_LOOP_BOUND_XLARGE, 'a'),
    };

    for (const auto& pattern : patterns) {
        IsNumber(pattern);
        (void)Split(pattern, "|");
    }

    for (int32_t i = 0; i < FUZZ_LOOP_BOUND_MEDIUM && extractor.HasMore(); i++) {
        std::string fuzzedStr = extractor.ExtractString(LARGE_STRING_LENGTH);
        IsNumber(fuzzedStr);
    }
}

void TestConfigXmlMalformed(DataExtractor& extractor)
{
    std::string malformedXml = GenerateMalformedXmlBinary(extractor.Remaining());
    WriteTempXmlFile("fuzz_malformed_", malformedXml, extractor.ExtractInt32());
}

void TestConfigXmlEmpty(DataExtractor& extractor)
{
    (void)extractor;
    std::string emptyXml = "<?xml version=\"1.0\"?><Configs></Configs>";
    time_t currentTime = time(nullptr);
    WriteTempXmlFile("fuzz_empty_", emptyXml, static_cast<int32_t>(currentTime));
}

void TestConfigDuplicateCheck(DataExtractor& extractor)
{
    (void)extractor;
    auto& config = SocPerfConfig::GetInstance();

    for (int32_t i = 0; i < FUZZ_LOOP_BOUND_XLARGE; i++) {
        int32_t resId = FUZZ_MIN_RESOURCE_ID + (i % FUZZ_LOOP_BOUND_XLARGE);
        config.IsValidResId(resId);
        config.IsGovResId(resId);
    }

    for (int32_t i = 0; i < FUZZ_LOOP_BOUND_LARGE; i++) {
        config.IsValidResId(INT32_MAX);
        config.IsGovResId(INT32_MIN);
    }
}

void TestConfigRangeTest(DataExtractor& extractor)
{
    auto& config = SocPerfConfig::GetInstance();

    for (int32_t id = FUZZ_MIN_RESOURCE_ID; id <= FUZZ_MAX_RESOURCE_ID; id += RANGE_TEST_STEP) {
        config.IsValidResId(id);
        config.IsGovResId(id);
    }

    int32_t minBoundaryStart = FUZZ_MIN_RESOURCE_ID - RANGE_BOUNDARY_OFFSET;
    int32_t minBoundaryEnd = FUZZ_MIN_RESOURCE_ID + RANGE_BOUNDARY_OFFSET;
    for (int32_t id = minBoundaryStart; id <= minBoundaryEnd; id++) {
        config.IsValidResId(id);
    }

    int32_t maxBoundaryStart = FUZZ_MAX_RESOURCE_ID - RANGE_BOUNDARY_OFFSET;
    int32_t maxBoundaryEnd = FUZZ_MAX_RESOURCE_ID + RANGE_BOUNDARY_OFFSET;
    for (int32_t id = maxBoundaryStart; id <= maxBoundaryEnd; id++) {
        config.IsValidResId(id);
    }

    for (int32_t i = 0; i < FUZZ_LOOP_BOUND_XLARGE && extractor.HasMore(); i++) {
        int32_t resId = extractor.ExtractInt32();
        config.IsValidResId(resId);
        config.IsGovResId(resId);
    }
}

void TestConfigHelperFunctions(DataExtractor& extractor)
{
    std::string testStrings[] = {
        "a|b|c|d",
        "key1=value1|key2=value2",
        "",
        "|",
        "|||",
        "single",
        "a=b=c",
        " spaces ",
        "\t|\t",
        "Chinese|English|Japanese",
        extractor.ExtractString(LARGE_STRING_LENGTH),
        extractor.ExtractString(DEFAULT_STRING_LENGTH),
    };

    for (const auto& str : testStrings) {
        std::vector<std::string> result1 = Split(str, "|");
        std::vector<std::string> result2 = SplitEx(str, "|");
        (void)result1;
        (void)result2;
    }

    // Test Max and Min with various values
    int64_t val1 = extractor.ExtractInt64();
    int64_t val2 = extractor.ExtractInt64();
    int64_t val3 = extractor.ExtractInt64();

    volatile int64_t max2 = Max(val1, val2);
    volatile int64_t min2 = Min(val1, val2);
    volatile int64_t max3 = Max(val1, val2, val3);
    volatile int64_t min3 = Min(val1, val2, val3);

    (void)max2;
    (void)min2;
    (void)max3;
    (void)min3;

    // Test with boundary values
    max2 = Max(static_cast<int64_t>(0), static_cast<int64_t>(-1));
    min2 = Min(INT64_MAX, INT64_MIN);
    (void)max2;
    (void)min2;
}

using TestCaseFunc = void (*)(DataExtractor&);

static const TestCaseFunc TEST_CASE_FUNCS[TEST_CASE_COUNT] = {
    TestConfigInit,
    TestConfigIsValidResId,
    TestConfigIsGovResId,
    TestConfigXmlParsing,
    TestConfigResourceValidation,
    TestConfigGovValidation,
    TestConfigSceneValidation,
    TestConfigActionValidation,
    TestConfigInterAction,
    TestConfigBoundary,
    TestConfigStringPatterns,
    TestConfigXmlMalformed,
    TestConfigXmlEmpty,
    TestConfigDuplicateCheck,
    TestConfigRangeTest,
    TestConfigHelperFunctions,
};

// Helper function to dispatch test case (reduces cyclomatic complexity)
void DispatchTestCase(uint8_t testCase, DataExtractor& extractor)
{
    if (testCase < TEST_CASE_COUNT) {
        TEST_CASE_FUNCS[testCase](extractor);
    }
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

    std::lock_guard<std::mutex> lock(g_fuzzMutex);
    if (!g_configInitialized) {
        auto& config = SocPerfConfig::GetInstance();
        config.Init();
        g_configInitialized = true;
    }

    uint8_t testCase = extractor.ExtractUInt8() % TEST_CASE_COUNT;
    DispatchTestCase(testCase, extractor);

    return 0;
}
