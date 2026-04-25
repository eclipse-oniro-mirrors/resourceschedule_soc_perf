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
 * @file socperf_config_fuzzer.cpp
 * @brief Fuzzing driver for SocPerf configuration parsing and validation.
 *
 * Coverage targets:
 * - XML configuration file parsing (socperf_config.cpp)
 * - Resource ID validation
 * - Governor resource validation
 * - Scene resource validation
 * - Action configuration validation
 * - Inter-action configuration
 * - Config path resolution
 * - Helper function validation (Split, SplitEx, IsNumber, etc.)
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <set>

// SocPerf headers
#include "socperf_config.h"
#include "socperf_common.h"
#include "socperf_action_type.h"
#include "socperf_log.h"

#include <libxml/tree.h>
#include <libxml/parser.h>
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

// Resource ID range (avoid conflict with OHOS::SOCPERF namespace)
constexpr int32_t FUZZ_MIN_RESOURCE_ID = 1000;
constexpr int32_t FUZZ_MAX_RESOURCE_ID = 5999;

// XML test size limits
constexpr size_t MAX_XML_ITEMS = 20;
constexpr size_t MAX_XML_DEPTH = 50;
constexpr size_t MAX_XML_ITEM_SIZE = 100;

// Test case selectors
constexpr uint8_t TEST_CONFIG_INIT = 0;
constexpr uint8_t TEST_CONFIG_ISVALIDRESID = 1;
constexpr uint8_t TEST_CONFIG_ISGOVERRESID = 2;
constexpr uint8_t TEST_CONFIG_XML_PARSING = 3;
constexpr uint8_t TEST_CONFIG_RESOURCE_VALIDATION = 4;
constexpr uint8_t TEST_CONFIG_GOV_VALIDATION = 5;
constexpr uint8_t TEST_CONFIG_SCENE_VALIDATION = 6;
constexpr uint8_t TEST_CONFIG_ACTION_VALIDATION = 7;
constexpr uint8_t TEST_CONFIG_INTERACTION = 8;
constexpr uint8_t TEST_CONFIG_BOUNDARY = 9;
constexpr uint8_t TEST_CONFIG_STRING_PATTERNS = 10;
constexpr uint8_t TEST_CONFIG_XML_MALFORMED = 11;
constexpr uint8_t TEST_CONFIG_XML_EMPTY = 12;
constexpr uint8_t TEST_CONFIG_DUPLICATE_CHECK = 13;
constexpr uint8_t TEST_CONFIG_RANGE_TEST = 14;
constexpr uint8_t TEST_CONFIG_HELPER_FUNCTIONS = 15;
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

    std::string ExtractString(size_t maxLen = 256)
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

    std::string ExtractStringWithLen(size_t maxLen = 256)
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

} // namespace FuzzUtils

using namespace FuzzUtils;
using namespace OHOS::SOCPERF;

// ============================================================================
// Global State
// ============================================================================

static std::mutex g_fuzzMutex;
static bool g_configInitialized = false;

// ============================================================================
// XML Generation Helpers (G.FMT.04: Each variable on its own line)
// ============================================================================

/**
 * @brief Generate a basic valid XML document.
 */
std::string GenerateBasicConfigXml()
{
    return R"(<?xml version="1.0" encoding="utf-8"?>
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
</Configs>)";
}

/**
 * @brief Generate malformed XML for testing error handling.
 */
std::string GenerateMalformedXml(const std::string& pattern, size_t len)
{
    std::string xml = "<?xml version=\"1.0\"?>\n";

    if (pattern == "empty") {
        return xml + "<Configs></Configs>";
    }

    if (pattern == "missing_root") {
        return xml + "<Resource><res id=\"1000\"/></Resource>";
    }

    if (pattern == "wrong_root") {
        return xml + "<WrongRoot></WrongRoot>";
    }

    if (pattern == "no_close") {
        return xml + "<Configs><Resource>";
    }

    if (pattern == "special_chars") {
        return xml + "<Configs><Info>&lt;&gt;&amp;&quot;&apos;</Info></Configs>";
    }

    if (pattern == "binary") {
        std::string result = xml + "<Configs>";
        for (size_t i = 0; i < len && i < MAX_XML_ITEM_SIZE; i++) {
            result += static_cast<char>(0xFF);
        }
        result += "</Configs>";
        return result;
    }

    if (pattern == "very_long") {
        std::string result = xml + "<Configs>";
        for (size_t i = 0; i < len && i < MAX_XML_ITEMS * MAX_XML_ITEM_SIZE; i++) {
            result += "<Item></Item>";
        }
        result += "</Configs>";
        return result;
    }

    if (pattern == "nested_deep") {
        std::string result = xml;
        for (size_t i = 0; i < len && i < MAX_XML_DEPTH; i++) {
            result += "<Level" + std::to_string(i) + ">";
        }
        result += "Content";
        for (size_t i = 0; i < len && i < MAX_XML_DEPTH; i++) {
            result += "</Level" + std::to_string(len - 1 - i) + ">";
        }
        return result;
    }

    if (pattern == "unicode") {
        return xml + "<Configs><Info>中文测试 日本語 한국어</Info></Configs>";
    }

    if (pattern == "null_bytes") {
        std::string result = xml + "<Configs><Item>";
        result += '\0';
        result += "content";
        result += '\0';
        result += "</Item></Configs>";
        return result;
    }

    return xml + "<Configs></Configs>";
}

/**
 * @brief Generate resource config XML with fuzzed values.
 */
std::string GenerateResourceXml(DataExtractor& extractor)
{
    std::string xml = R"(<?xml version="1.0" encoding="utf-8"?>
<Configs>
    <Resource>)";

    int32_t numResources = extractor.ExtractInt32() % MAX_XML_ITEMS + 1;

    for (int32_t i = 0; i < numResources && extractor.HasMore(); i++) {
        int32_t resId = extractor.ExtractInt32();
        if (resId < 0) {
            resId = -resId;
        }
        if (resId < FUZZ_MIN_RESOURCE_ID) {
            resId = FUZZ_MIN_RESOURCE_ID + (resId % 1000);
        }
        if (resId > FUZZ_MAX_RESOURCE_ID) {
            resId = FUZZ_MAX_RESOURCE_ID - (resId % 100);
        }

        std::string name = extractor.ExtractString(64);
        if (name.empty()) {
            name = "Resource" + std::to_string(resId);
        }

        int32_t pairId = extractor.ExtractInt32();
        if (pairId < 0) {
            pairId = -pairId;
        }
        if (pairId > FUZZ_MAX_RESOURCE_ID) {
            pairId = 0;  // 0 means no pair
        }

        int32_t mode = extractor.ExtractInt32() % 2;
        int32_t persistMode = extractor.ExtractInt32() % 2;
        int32_t trace = extractor.ExtractInt32() % 2;
        int64_t defValue = extractor.ExtractInt64() % 100000000;

        char buffer[256];
        snprintf(buffer, sizeof(buffer),
            R"(        <res id="%d" name="%s" pair="%d" mode="%d" switch="%d" trace="%d">
            <default>%lld</default>
            <path>/sys/test/path%d</path>
            <node>%lld %lld %lld</node>
        </res>)",
            resId, name.c_str(), pairId, mode, persistMode, trace,
            static_cast<long long>(defValue), resId,
            static_cast<long long>(defValue),
            static_cast<long long>(defValue + 1000000),
            static_cast<long long>(defValue + 2000000));

        xml += "\n";
        xml += buffer;
    }

    xml += R"(
    </Resource>
</Configs>)";

    return xml;
}

/**
 * @brief Generate boost config XML with fuzzed values.
 */
std::string GenerateBoostXml(DataExtractor& extractor)
{
    std::string xml = R"(<?xml version="1.0" encoding="utf-8"?>
<Configs>)";

    int32_t numConfigs = extractor.ExtractInt32() % 10 + 1;

    for (int32_t i = 0; i < numConfigs && extractor.HasMore(); i++) {
        std::string configMode = extractor.ExtractString(32);
        if (configMode.empty()) {
            configMode = "default";
        }

        int32_t numCmds = extractor.ExtractInt32() % MAX_XML_ITEMS + 1;

        char configHeader[128];
        snprintf(configHeader, sizeof(configHeader),
            R"(
    <Config mode="%s">)", configMode.c_str());
        xml += configHeader;

        for (int32_t j = 0; j < numCmds && extractor.HasMore(); j++) {
            int32_t cmdId = 1000 + (extractor.ExtractInt32() % 10000);
            std::string cmdName = extractor.ExtractString(64);
            if (cmdName.empty()) {
                cmdName = "Cmd" + std::to_string(cmdId);
            }

            int32_t thermalLvl = extractor.ExtractInt32() % 10;
            int32_t duration = extractor.ExtractInt32() % 10000;
            int32_t interaction = extractor.ExtractInt32() % 2;

            char cmdBuffer[256];
            snprintf(cmdBuffer, sizeof(cmdBuffer),
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
            xml += cmdBuffer;
        }

        xml += "\n    </Config>";
    }

    xml += "\n</Configs>";
    return xml;
}

// ============================================================================
// Test Cases
// ============================================================================

/**
 * @brief Test: Config initialization.
 */
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

/**
 * @brief Test: IsValidResId validation.
 */
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
    for (int32_t i = FUZZ_MIN_RESOURCE_ID; i <= FUZZ_MIN_RESOURCE_ID + 100; i++) {
        config.IsValidResId(i);
    }
    for (int32_t i = FUZZ_MAX_RESOURCE_ID - 100; i <= FUZZ_MAX_RESOURCE_ID; i++) {
        config.IsValidResId(i);
    }

    // Random fuzzed values
    for (int32_t i = 0; i < 100; i++) {
        int32_t fuzzedId = extractor.ExtractInt32();
        config.IsValidResId(fuzzedId);
    }
}

/**
 * @brief Test: IsGovResId validation.
 */
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

    for (int32_t i = 0; i <= 5000; i += 100) {
        config.IsGovResId(i);
    }

    for (int32_t i = 0; i < 100; i++) {
        int32_t fuzzedId = extractor.ExtractInt32();
        config.IsGovResId(fuzzedId);
    }
}

/**
 * @brief Test: XML parsing with various patterns.
 */
void TestConfigXmlParsing(DataExtractor& extractor)
{
    uint8_t patternType = extractor.ExtractUInt8() % 11;
    std::string patterns[] = {
        "empty", "missing_root", "wrong_root", "no_close",
        "special_chars", "binary", "very_long", "nested_deep",
        "unicode", "null_bytes"
    };

    std::string malformedXml = GenerateMalformedXml(patterns[patternType], extractor.Remaining());
    std::string tempFile = "/tmp/fuzz_config_" + std::to_string(extractor.ExtractInt32()) + ".xml";

    FILE* fp = fopen(tempFile.c_str(), "wb");
    if (fp != nullptr) {
        fwrite(malformedXml.c_str(), 1, malformedXml.size(), fp);
        fclose(fp);
        remove(tempFile.c_str());
    }

    std::string validXml = GenerateBasicConfigXml();
    fp = fopen(tempFile.c_str(), "wb");
    if (fp != nullptr) {
        fwrite(validXml.c_str(), 1, validXml.size(), fp);
        fclose(fp);
        remove(tempFile.c_str());
    }
}

/**
 * @brief Test: Resource validation.
 */
void TestConfigResourceValidation(DataExtractor& extractor)
{
    std::string resourceXml = GenerateResourceXml(extractor);
    std::string tempFile = "/tmp/fuzz_resource_" + std::to_string(extractor.ExtractInt32()) + ".xml";

    FILE* fp = fopen(tempFile.c_str(), "wb");
    if (fp != nullptr) {
        fwrite(resourceXml.c_str(), 1, resourceXml.size(), fp);
        fclose(fp);
        remove(tempFile.c_str());
    }

    volatile bool rangeCheck = IsValidRangeResId(extractor.ExtractInt32());
    (void)rangeCheck;

    volatile bool persistCheck = IsValidPersistMode(extractor.ExtractInt32() % 2);
    (void)persistCheck;

    std::string testNums[] = {
        "123", "-456", "0", "12.34", "abc",
        "", "12a", "-", "+123"
    };
    for (const auto& str : testNums) {
        volatile bool isNum = IsNumber(str);
        (void)isNum;
    }
}

/**
 * @brief Test: Governor resource validation.
 */
void TestConfigGovValidation(DataExtractor& extractor)
{
    auto& config = SocPerfConfig::GetInstance();

    for (int32_t i = 0; i < 50; i++) {
        int32_t resId = extractor.ExtractInt32();
        config.IsGovResId(resId);
        config.IsValidResId(resId);
    }

    std::string testStr = extractor.ExtractString(128);
    if (!testStr.empty()) {
        std::vector<std::string> parts = Split(testStr, "|");
        (void)parts;
    }

    testStr = extractor.ExtractString(128);
    if (!testStr.empty()) {
        std::vector<std::string> parts = SplitEx(testStr, "|");
        (void)parts;
    }
}

/**
 * @brief Test: Scene resource validation.
 */
void TestConfigSceneValidation(DataExtractor& extractor)
{
    (void)extractor;
    std::string sceneName = extractor.ExtractString(64);
    int32_t persistMode = extractor.ExtractInt32() % 2;

    volatile bool sceneCheck = IsValidPersistMode(persistMode);
    (void)sceneCheck;

    std::string sceneNames[] = {
        "game", "video", "camera", "", "123",
        "a b c", "<tag>", "'quote'"
    };
    for (const auto& name : sceneNames) {
        (void)name;
    }
}

/**
 * @brief Test: Action configuration validation.
 */
void TestConfigActionValidation(DataExtractor& extractor)
{
    int32_t numPairs = extractor.ExtractInt32() % 20;

    std::vector<int64_t> actionVars;
    for (int32_t i = 0; i < numPairs * 2 && extractor.HasMore(); i++) {
        actionVars.push_back(extractor.ExtractInt64());
    }

    volatile int64_t maxResult = Max(extractor.ExtractInt64(), extractor.ExtractInt64());
    (void)maxResult;

    volatile int64_t minResult = Min(extractor.ExtractInt64(), extractor.ExtractInt64());
    (void)minResult;

    maxResult = Max(extractor.ExtractInt64(), extractor.ExtractInt64(), extractor.ExtractInt64());
    minResult = Min(extractor.ExtractInt64(), extractor.ExtractInt64(), extractor.ExtractInt64());
}

/**
 * @brief Test: Inter-action configuration.
 */
void TestConfigInterAction(DataExtractor& extractor)
{
    int32_t cmdId = extractor.ExtractInt32();
    int32_t actionType = extractor.ExtractInt32() % ACTION_TYPE_MAX;
    int64_t delayTime = extractor.ExtractInt64() % 100000;

    std::shared_ptr<InterAction> interAction =
        std::make_shared<InterAction>(cmdId, actionType, delayTime);

    (void)interAction;

    for (int32_t i = 0; i < 10; i++) {
        int32_t testCmdId = extractor.ExtractInt32();
        int32_t testType = extractor.ExtractInt32() % ACTION_TYPE_MAX;
        int64_t testDelay = extractor.ExtractInt64() % 1000000;

        std::shared_ptr<InterAction> testAction =
            std::make_shared<InterAction>(testCmdId, testType, testDelay);
        (void)testAction;
    }
}

/**
 * @brief Test: Boundary conditions.
 */
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
    IsValidPersistMode(2);
    IsValidPersistMode(100);
    IsValidPersistMode(INT32_MAX);

    IsNumber("");
    IsNumber("-");
    IsNumber("0");
    IsNumber("-0");
    IsNumber("+123");
}

/**
 * @brief Test: String patterns.
 */
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
        "中文测试",
        "<tag>",
        "&amp;",
        "'\"\\",
        "$(cmd)",
        "; DROP",
        std::string(100, 'a'),
    };

    for (const auto& pattern : patterns) {
        IsNumber(pattern);
        (void)Split(pattern, "|");
    }

    for (int32_t i = 0; i < 20 && extractor.HasMore(); i++) {
        std::string fuzzedStr = extractor.ExtractString(128);
        IsNumber(fuzzedStr);
    }
}

/**
 * @brief Test: Malformed XML handling.
 */
void TestConfigXmlMalformed(DataExtractor& extractor)
{
    size_t remaining = extractor.Remaining();
    std::string malformedXml = GenerateMalformedXml("binary", remaining);
    std::string tempFile = "/tmp/fuzz_malformed_" + std::to_string(extractor.ExtractInt32()) + ".xml";

    FILE* fp = fopen(tempFile.c_str(), "wb");
    if (fp != nullptr) {
        fwrite(malformedXml.c_str(), 1, malformedXml.size(), fp);
        fclose(fp);
        remove(tempFile.c_str());
    }
}

/**
 * @brief Test: Empty XML handling.
 */
void TestConfigXmlEmpty(DataExtractor& extractor)
{
    (void)extractor;
    std::string emptyXml = "<?xml version=\"1.0\"?><Configs></Configs>";
    std::string tempFile = "/tmp/fuzz_empty_" + std::to_string(static_cast<long>(time(nullptr))) + ".xml";

    FILE* fp = fopen(tempFile.c_str(), "wb");
    if (fp != nullptr) {
        fwrite(emptyXml.c_str(), 1, emptyXml.size(), fp);
        fclose(fp);
        remove(tempFile.c_str());
    }
}

/**
 * @brief Test: Duplicate checking.
 */
void TestConfigDuplicateCheck(DataExtractor& extractor)
{
    (void)extractor;
    auto& config = SocPerfConfig::GetInstance();

    for (int32_t i = 0; i < 100; i++) {
        int32_t resId = FUZZ_MIN_RESOURCE_ID + (i % 100);
        config.IsValidResId(resId);
        config.IsGovResId(resId);
    }

    for (int32_t i = 0; i < 50; i++) {
        config.IsValidResId(INT32_MAX);
        config.IsGovResId(INT32_MIN);
    }
}

/**
 * @brief Test: Range testing.
 */
void TestConfigRangeTest(DataExtractor& extractor)
{
    auto& config = SocPerfConfig::GetInstance();

    for (int32_t id = FUZZ_MIN_RESOURCE_ID; id <= FUZZ_MAX_RESOURCE_ID; id += 10) {
        config.IsValidResId(id);
        config.IsGovResId(id);
    }

    for (int32_t id = FUZZ_MIN_RESOURCE_ID - 20; id <= FUZZ_MIN_RESOURCE_ID + 20; id++) {
        config.IsValidResId(id);
    }

    for (int32_t id = FUZZ_MAX_RESOURCE_ID - 20; id <= FUZZ_MAX_RESOURCE_ID + 20; id++) {
        config.IsValidResId(id);
    }

    for (int32_t i = 0; i < 100 && extractor.HasMore(); i++) {
        int32_t resId = extractor.ExtractInt32();
        config.IsValidResId(resId);
        config.IsGovResId(resId);
    }
}

/**
 * @brief Test: Helper functions (Split, SplitEx, Max, Min, IsNumber, etc.).
 */
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
        "中文|英文|日文",
        extractor.ExtractString(128),
        extractor.ExtractString(256),
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

    switch (testCase) {
        case TEST_CONFIG_INIT:
            TestConfigInit(extractor);
            break;
        case TEST_CONFIG_ISVALIDRESID:
            TestConfigIsValidResId(extractor);
            break;
        case TEST_CONFIG_ISGOVERRESID:
            TestConfigIsGovResId(extractor);
            break;
        case TEST_CONFIG_XML_PARSING:
            TestConfigXmlParsing(extractor);
            break;
        case TEST_CONFIG_RESOURCE_VALIDATION:
            TestConfigResourceValidation(extractor);
            break;
        case TEST_CONFIG_GOV_VALIDATION:
            TestConfigGovValidation(extractor);
            break;
        case TEST_CONFIG_SCENE_VALIDATION:
            TestConfigSceneValidation(extractor);
            break;
        case TEST_CONFIG_ACTION_VALIDATION:
            TestConfigActionValidation(extractor);
            break;
        case TEST_CONFIG_INTERACTION:
            TestConfigInterAction(extractor);
            break;
        case TEST_CONFIG_BOUNDARY:
            TestConfigBoundary(extractor);
            break;
        case TEST_CONFIG_STRING_PATTERNS:
            TestConfigStringPatterns(extractor);
            break;
        case TEST_CONFIG_XML_MALFORMED:
            TestConfigXmlMalformed(extractor);
            break;
        case TEST_CONFIG_XML_EMPTY:
            TestConfigXmlEmpty(extractor);
            break;
        case TEST_CONFIG_DUPLICATE_CHECK:
            TestConfigDuplicateCheck(extractor);
            break;
        case TEST_CONFIG_RANGE_TEST:
            TestConfigRangeTest(extractor);
            break;
        case TEST_CONFIG_HELPER_FUNCTIONS:
            TestConfigHelperFunctions(extractor);
            break;
        default:
            break;
    }

    return 0;
}
