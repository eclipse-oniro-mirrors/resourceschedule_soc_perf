/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "socperfconfig_resource_fuzzer.h"

#include <cctype>
#include <memory>
#include <string>
#include <vector>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "socperf_fuzz_utils.h"

#define private public
#define protected public
#include "socperf_config.h"
#undef private
#undef protected

namespace OHOS {
namespace SOCPERF {
namespace {
class XmlDocument {
public:
    explicit XmlDocument(const std::string& xml)
    {
        xmlKeepBlanksDefault(0);
        doc_ = xmlReadMemory(xml.c_str(), static_cast<int>(xml.size()), "socperf_resource_fuzz.xml",
            nullptr, XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
        if (doc_ != nullptr) {
            root_ = xmlDocGetRootElement(doc_);
        }
    }

    ~XmlDocument()
    {
        if (doc_ != nullptr) {
            xmlFreeDoc(doc_);
            doc_ = nullptr;
            root_ = nullptr;
        }
    }

    bool IsValid() const
    {
        return root_ != nullptr;
    }

    xmlDoc* doc_ = nullptr;
    xmlNode* root_ = nullptr;
};

std::string SanitizeName(const std::string& source, const std::string& fallback)
{
    std::string value = source.empty() ? fallback : source;
    for (char& ch : value) {
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_') {
            ch = '_';
        }
    }
    if (value.empty()) {
        value = fallback;
    }
    return value;
}

xmlNode* FindChild(xmlNode* parent, const char* name)
{
    for (xmlNode* child = parent == nullptr ? nullptr : parent->children; child != nullptr; child = child->next) {
        if (!xmlStrcmp(child->name, reinterpret_cast<const xmlChar*>(name))) {
            return child;
        }
    }
    return nullptr;
}

void ResetConfig(SocPerfConfig& config)
{
    config.resourceNodeInfo_.clear();
    config.sceneResourceInfo_.clear();
    config.configPerfActionsInfo_.clear();
    config.interAction_.clear();
    config.reportFunc_ = nullptr;
    config.scenarioFunc_ = nullptr;
    config.minThermalLvl_ = INVALID_THERMAL_LVL;
}

std::string BuildValidResourceXml(FuzzDataProvider& provider)
{
    std::string sceneName = SanitizeName(provider.ConsumeString(12), "display");
    std::string sceneItem1 = SanitizeName(provider.ConsumeString(12), "open");
    std::string sceneItem2 = SanitizeName(provider.ConsumeString(12), "fold");
    int32_t trace1 = provider.ConsumeBool() ? 1 : 0;
    int32_t trace2 = provider.ConsumeBool() ? 1 : 0;
    int32_t trace3 = provider.ConsumeBool() ? 1 : 0;
    int32_t cpuMin = provider.ConsumeInt32InRange(100, 120);
    int32_t cpuMid = provider.ConsumeInt32InRange(180, 220);
    int32_t cpuMax = provider.ConsumeInt32InRange(260, 320);
    int32_t ddrMin = provider.ConsumeInt32InRange(200, 240);
    int32_t ddrMid = provider.ConsumeInt32InRange(300, 360);
    int32_t ddrMax = provider.ConsumeInt32InRange(400, 480);
    return "<Configs>"
        "<Resource>"
        "<res id=\"1000\" name=\"cpu_max\" pair=\"1001\" mode=\"1\" switch=\"1\" trace=\"" +
        std::to_string(trace1) + "\">"
        "<default>" + std::to_string(cpuMax) + "</default>"
        "<node>" + std::to_string(cpuMin) + " " + std::to_string(cpuMid) + " " + std::to_string(cpuMax) + "</node>"
        "</res>"
        "<res id=\"1001\" name=\"cpu_min\" pair=\"1000\" mode=\"0\" switch=\"1\" trace=\"" +
        std::to_string(trace2) + "\">"
        "<default>" + std::to_string(cpuMin) + "</default>"
        "<node>" + std::to_string(cpuMin) + " " + std::to_string(cpuMid) + " " + std::to_string(cpuMax) + "</node>"
        "</res>"
        "<res id=\"1003\" name=\"ddr_freq\" switch=\"0\" trace=\"" + std::to_string(trace3) + "\">"
        "<default>" + std::to_string(ddrMid) + "</default>"
        "<path>/tmp/socperf_ddr_freq</path>"
        "<node>" + std::to_string(ddrMin) + " " + std::to_string(ddrMid) + " " + std::to_string(ddrMax) + "</node>"
        "</res>"
        "</Resource>"
        "<GovResource>"
        "<res id=\"1002\" name=\"cpu_gov\" switch=\"0\" trace=\"1\">"
        "<default>1</default>"
        "<path>/tmp/socperf_gov0</path>"
        "<path>/tmp/socperf_gov1</path>"
        "<node level=\"1\">powersave|schedutil</node>"
        "<node level=\"2\">performance|userspace</node>"
        "</res>"
        "</GovResource>"
        "<SceneResource>"
        "<scene name=\"" + sceneName + "\" switch=\"1\">"
        "<item req=\"1\">" + sceneItem1 + "</item>"
        "<item req=\"0\">" + sceneItem2 + "</item>"
        "</scene>"
        "</SceneResource>"
        "<Info>"
        "<inf path=\"/system/lib64/libsocperf_fuzz_fake.so\" func=\"ReportData\" scenarioFunc=\"ReportScene\"/>"
        "</Info>"
        "</Configs>";
}

std::string BuildInvalidResourceXml(FuzzDataProvider& provider)
{
    std::string invalidName = SanitizeName(provider.ConsumeString(8), "broken");
    return "<Configs>"
        "<Resource>"
        "<res id=\"bad\" name=\"" + invalidName + "\" pair=\"99999\" mode=\"x\" switch=\"3\">"
        "<default>oops</default>"
        "<node>1 bad</node>"
        "</res>"
        "</Resource>"
        "<GovResource>"
        "<res id=\"1002\" name=\"bad_gov\" switch=\"0\">"
        "<default>bad</default>"
        "<path>/tmp/gov_only</path>"
        "<node level=\"x\">single</node>"
        "</res>"
        "</GovResource>"
        "<SceneResource>"
        "<scene switch=\"2\">"
        "<item req=\"x\">invalid</item>"
        "</scene>"
        "</SceneResource>"
        "</Configs>";
}

void RunFileCases(FuzzDataProvider& provider)
{
    SocPerfConfig config;
    ResetConfig(config);
    (void)config.GetRealConfigPath(SOCPERF_RESOURCE_CONFIG_XML);
    (void)config.GetRealConfigPath(provider.ConsumeString(32));
    (void)config.GetAllRealConfigPath(SOCPERF_RESOURCE_CONFIG_XML);
    (void)config.GetAllRealConfigPath(provider.ConsumeString(32));
    (void)config.LoadAllConfigXmlFile(SOCPERF_RESOURCE_CONFIG_XML);
    (void)config.LoadAllConfigXmlFile(provider.ConsumeString(32));
    (void)config.LoadConfigXmlFile("");

    ScopedTempFile validFile("socperf_resource_valid", BuildValidResourceXml(provider));
    if (validFile.IsValid()) {
        (void)config.LoadConfigXmlFile(validFile.GetPath());
    }

    ScopedTempFile invalidFile("socperf_resource_invalid", BuildInvalidResourceXml(provider));
    if (invalidFile.IsValid()) {
        (void)config.LoadConfigXmlFile(invalidFile.GetPath());
    }

    ScopedTempFile wrongRootFile("socperf_wrong_root", "<WrongRoot/>");
    if (wrongRootFile.IsValid()) {
        (void)config.LoadConfigXmlFile(wrongRootFile.GetPath());
    }
}

void RunDirectParserCases(FuzzDataProvider& provider)
{
    SocPerfConfig config;
    ResetConfig(config);
    XmlDocument validXml(BuildValidResourceXml(provider));
    if (!validXml.IsValid()) {
        return;
    }

    (void)config.ParseResourceXmlFile(validXml.root_, "mem_resource.xml", validXml.doc_);
    xmlNode* resourceNode = FindChild(validXml.root_, "Resource");
    xmlNode* govNode = FindChild(validXml.root_, "GovResource");
    xmlNode* sceneNode = FindChild(validXml.root_, "SceneResource");
    xmlNode* infoNode = FindChild(validXml.root_, "Info");

    if (resourceNode != nullptr) {
        (void)config.LoadResource(resourceNode, "mem_resource.xml");
        xmlNode* firstResNode = FindChild(resourceNode, "res");
        if (firstResNode != nullptr) {
            (void)config.TraversalFreqResource(firstResNode, "mem_resource.xml");
            auto manualResNode = std::make_shared<ResNode>(1100, "manual_res", MAX_FREQUE_NODE, INVALID_VALUE,
                REPORT_TO_PERFSO);
            (void)config.LoadFreqResourceContent(REPORT_TO_PERFSO, firstResNode->children, "mem_resource.xml",
                manualResNode);
        }
    }

    if (govNode != nullptr) {
        (void)config.LoadGovResource(govNode, "mem_resource.xml");
        xmlNode* firstGovRes = FindChild(govNode, "res");
        if (firstGovRes != nullptr) {
            auto manualGovNode = std::make_shared<GovResNode>(1102, "manual_gov", WRITE_NODE);
            manualGovNode->paths.push_back("/tmp/manual_gov0");
            manualGovNode->paths.push_back("/tmp/manual_gov1");
            (void)config.TraversalGovResource(WRITE_NODE, firstGovRes->children, "mem_resource.xml", manualGovNode);
        }
    }

    if (sceneNode != nullptr) {
        (void)config.LoadSceneResource(sceneNode, "mem_resource.xml");
        (void)config.LoadSceneResource(sceneNode, "mem_resource.xml");
        xmlNode* firstScene = FindChild(sceneNode, "scene");
        if (firstScene != nullptr) {
            auto manualScene = std::make_shared<SceneResNode>("manual_scene", REPORT_TO_PERFSO);
            (void)config.TraversalSceneResource(firstScene->children, "mem_resource.xml", manualScene);
        }
    }

    if (infoNode != nullptr) {
        config.LoadInfo(infoNode, "mem_resource.xml");
    }

    XmlDocument invalidXml(BuildInvalidResourceXml(provider));
    if (invalidXml.IsValid()) {
        (void)config.ParseResourceXmlFile(invalidXml.root_, "mem_resource_invalid.xml", invalidXml.doc_);
    }
}

void RunValidationCases()
{
    SocPerfConfig config;
    ResetConfig(config);

    (void)config.CheckTrace("1");
    (void)config.CheckTrace("0");
    (void)config.CheckTrace("trace");

    (void)config.CheckSceneResourceTag(nullptr, "1", "scene.xml");
    (void)config.CheckSceneResourceTag("display", "3", "scene.xml");
    (void)config.CheckSceneResourceTag("display", "1", "scene.xml");

    (void)config.CheckResourcePersistMode("3", "resource.xml");
    (void)config.CheckResourcePersistMode("1", "resource.xml");
    (void)config.CheckResourceTag("bad", "cpu", nullptr, nullptr, "1", "resource.xml");
    (void)config.CheckResourceTag("1000", nullptr, nullptr, nullptr, "1", "resource.xml");
    (void)config.CheckResourceTag("1000", "cpu", "bad", nullptr, "1", "resource.xml");
    (void)config.CheckResourceTag("1000", "cpu", "1001", "bad", "1", "resource.xml");
    (void)config.CheckResourceTag("1000", "cpu", "1001", "0", "1", "resource.xml");
    (void)config.CheckResourceTag(REPORT_TO_PERFSO, nullptr, nullptr, "resource.xml");
    (void)config.CheckResourceTag(WRITE_NODE, "200", nullptr, "resource.xml");
    (void)config.CheckResourceTag(WRITE_NODE, "200", "/tmp/test_node", "resource.xml");

    auto resNode = std::make_shared<ResNode>(1000, "cpu", MAX_FREQUE_NODE, 1001, REPORT_TO_PERFSO);
    (void)config.LoadResourceAvailable(resNode, "100 200 300");
    (void)config.LoadResourceAvailable(resNode, "100 bad");

    auto invalidPairNode = std::make_shared<ResNode>(1001, "cpu_pair", 0, 1999, REPORT_TO_PERFSO);
    invalidPairNode->def = 250;
    invalidPairNode->available.insert(200);
    config.resourceNodeInfo_[1000] = resNode;
    config.resourceNodeInfo_[1001] = invalidPairNode;
    (void)config.CheckPairResIdValid();
    (void)config.CheckDefValid();

    auto validPairNode = std::make_shared<ResNode>(1001, "cpu_pair", 0, 1000, REPORT_TO_PERFSO);
    resNode->pair = 1001;
    resNode->def = 300;
    resNode->available.insert(300);
    validPairNode->def = 200;
    validPairNode->available.insert(200);
    config.resourceNodeInfo_[1001] = validPairNode;
    (void)config.CheckPairResIdValid();
    (void)config.CheckDefValid();

    auto govNode = std::make_shared<GovResNode>(1002, "gov", WRITE_NODE);
    govNode->paths.push_back("/tmp/gov0");
    govNode->paths.push_back("/tmp/gov1");
    (void)config.LoadGovResourceAvailable(govNode, "1", "performance|schedutil");
    (void)config.LoadGovResourceAvailable(govNode, "2", "performance");
    (void)config.CheckGovResourceTag(nullptr, "gov", "0", "gov.xml");
    (void)config.CheckGovResourceTag("1002", nullptr, "0", "gov.xml");
    (void)config.CheckGovResourceTag("1002", "gov", "9", "gov.xml");
    (void)config.CheckGovResourceTag("1002", "gov", "0", "gov.xml");

    config.ReportConfigLoadAbnormal("resource.xml", "resource fuzz abnormal", -1);
}
} // namespace

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzDataProvider provider(data, size);
    RunFileCases(provider);
    RunDirectParserCases(provider);
    RunValidationCases();
    return true;
}
} // namespace SOCPERF
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SOCPERF::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
