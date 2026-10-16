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

#include "socperfconfig_boost_fuzzer.h"

#include <cctype>
#include <memory>
#include <string>
#include <vector>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "socperf_fuzz_utils.h"
#include "socperf_config.h"

namespace OHOS {
namespace SOCPERF {
namespace {
constexpr int32_t FUZZ_MANUAL_ACTIONS_CMD_ID = 22000;
constexpr int32_t FUZZ_MODE_ACTIONS_CMD_ID = 23000;

class XmlDocument {
public:
    explicit XmlDocument(const std::string& xml)
    {
        xmlKeepBlanksDefault(0);
        doc_ = xmlReadMemory(xml.c_str(), static_cast<int>(xml.size()), "socperf_boost_fuzz.xml",
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

int ReportDataStub(const std::vector<int32_t>&, const std::vector<int64_t>&,
    const std::vector<int64_t>&, const std::string&)
{
    return 0;
}

int ReportSceneStub(const std::string&)
{
    return 0;
}

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

std::string BuildBootstrapResourceXml()
{
    return "<Configs>"
        "<Resource>"
        "<res id=\"1000\" name=\"cpu_max\" pair=\"1001\" mode=\"1\" switch=\"1\">"
        "<default>300</default><node>100 200 300</node></res>"
        "<res id=\"1001\" name=\"cpu_min\" pair=\"1000\" mode=\"0\" switch=\"1\">"
        "<default>100</default><node>100 200 300</node></res>"
        "<res id=\"1003\" name=\"gpu_freq\" switch=\"1\">"
        "<default>500</default><node>300 400 500</node></res>"
        "</Resource>"
        "</Configs>";
}

void PrimeResourceConfig(SocPerfConfig& config)
{
    XmlDocument bootstrap(BuildBootstrapResourceXml());
    if (!bootstrap.IsValid()) {
        return;
    }
    (void)config.ParseResourceXmlFile(bootstrap.root_, "bootstrap_resource.xml", bootstrap.doc_);
}

std::string BuildBoostXml(FuzzDataProvider& provider, bool withConfigTag)
{
    std::string configMode = SanitizeName(provider.ConsumeString(12), "display");
    std::string cmdName = SanitizeName(provider.ConsumeString(12), "boost_main");
    int32_t thermalLevel = provider.ConsumeInt32InRange(0, 3);
    int32_t perfHigh = provider.ConsumeInt32InRange(220, 300);
    int32_t perfMid = provider.ConsumeInt32InRange(160, 220);
    int32_t perfLow = provider.ConsumeInt32InRange(100, 160);

    std::string body =
        "<interaction><weak id=\"21000\" delay=\"1\" type=\"1\"/></interaction>"
        "<cmd id=\"21000\" name=\"" + cmdName + "\" interaction=\"0\" mode=\"" + configMode +
        "=21001|" + configMode + "=21002\">"
        "<act thermalLvl=\"" + std::to_string(thermalLevel) + "\" thermalCmdId=\"21003\">"
        "<duration>1</duration>"
        "<cpu_max>" + std::to_string(perfHigh) + "</cpu_max>"
        "<cpu_min>" + std::to_string(perfLow) + "</cpu_min>"
        "</act>"
        "<act>"
        "<duration>0</duration>"
        "<cpu_max>" + std::to_string(perfMid) + "</cpu_max>"
        "<gpu_freq>400</gpu_freq>"
        "</act>"
        "</cmd>"
        "<cmd id=\"21001\" name=\"scene_perf\">"
        "<act><duration>1</duration><cpu_max>250</cpu_max></act>"
        "</cmd>"
        "<cmd id=\"21003\" name=\"thermal_perf\">"
        "<act thermalLvl=\"0\"><duration>1</duration><cpu_max>150</cpu_max></act>"
        "</cmd>";
    if (withConfigTag) {
        return "<Configs><Config mode=\"" + configMode + "\">" + body + "</Config></Configs>";
    }
    return "<Configs>" + body + "</Configs>";
}

std::string BuildInvalidBoostXml()
{
    return "<Configs>"
        "<Config mode=\"broken\">"
        "<cmd id=\"bad\" name=\"oops\">"
        "<act thermalLvl=\"x\" thermalCmdId=\"bad\">"
        "<duration>bad</duration>"
        "<unknown>oops</unknown>"
        "</act>"
        "</cmd>"
        "</Config>"
        "</Configs>";
}

void RunBoostFileCases(FuzzDataProvider& provider)
{
    SocPerfConfig config;
    ResetConfig(config);
    PrimeResourceConfig(config);

    config.InitPerfFunc(nullptr, nullptr, nullptr);
    config.InitPerfFunc("/system/lib64/libsocperf_not_exist.so", "ReportData", "ReportScene");
    config.reportFunc_ = ReportDataStub;
    config.scenarioFunc_ = ReportSceneStub;
    config.InitPerfFunc("/system/lib64/libsocperf_ignore.so", "ReportData", "ReportScene");
    config.reportFunc_ = nullptr;
    config.scenarioFunc_ = nullptr;

    ScopedTempFile validConfigFile("socperf_boost_config", BuildBoostXml(provider, true));
    if (validConfigFile.IsValid()) {
        (void)config.LoadConfigXmlFile(validConfigFile.GetPath());
    }

    ScopedTempFile validPlainFile("socperf_boost_plain", BuildBoostXml(provider, false));
    if (validPlainFile.IsValid()) {
        (void)config.LoadConfigXmlFile(validPlainFile.GetPath());
    }

    ScopedTempFile invalidFile("socperf_boost_invalid", BuildInvalidBoostXml());
    if (invalidFile.IsValid()) {
        (void)config.LoadConfigXmlFile(invalidFile.GetPath());
    }
}

void RunDirectParserCases(FuzzDataProvider& provider)
{
    SocPerfConfig config;
    ResetConfig(config);
    PrimeResourceConfig(config);

    XmlDocument configTagXml(BuildBoostXml(provider, true));
    if (configTagXml.IsValid()) {
        (void)config.ParseBoostXmlFile(configTagXml.root_, "mem_boost.xml", configTagXml.doc_);
        (void)config.LoadConfig(configTagXml.root_, "mem_boost.xml");
        (void)config.IsConfigTag(configTagXml.root_);
        (void)config.HandleConfigNode(configTagXml.root_->children, "mem_boost.xml");
        xmlNode* configNode = FindChild(configTagXml.root_, "Config");
        if (configNode != nullptr) {
            (void)config.GetConfigMode(configNode);
            (void)config.LoadConfigInfo(configNode, "mem_boost.xml", DEFAULT_CONFIG_MODE);
            xmlNode* cmdNode = FindChild(configNode, "cmd");
            if (cmdNode != nullptr) {
                (void)config.LoadCmdInfo(cmdNode, "mem_boost.xml", DEFAULT_CONFIG_MODE);
                auto manualActions = std::make_shared<Actions>(FUZZ_MANUAL_ACTIONS_CMD_ID,
                    "manual_actions");
                (void)config.TraversalBoostResource(cmdNode->children, "mem_boost.xml", manualActions);
            }
        }
    }

    XmlDocument plainXml(BuildBoostXml(provider, false));
    if (plainXml.IsValid()) {
        (void)config.IsConfigTag(plainXml.root_);
        (void)config.LoadConfig(plainXml.root_, "mem_plain.xml");
        (void)config.LoadConfigInfo(plainXml.root_, "mem_plain.xml", DEFAULT_CONFIG_MODE);
    }
}

void RunNodeLevelCases()
{
    SocPerfConfig config;
    ResetConfig(config);
    PrimeResourceConfig(config);

    auto actions = std::make_shared<Actions>(FUZZ_MODE_ACTIONS_CMD_ID, "mode_actions");
    config.ParseModeCmd("display=23001|display=23002|camera=23003|bad|scene=nope", "mode.xml", actions);

    XmlDocument durationXml("<act><duration>1</duration></act>");
    if (durationXml.IsValid()) {
        auto action = std::make_shared<Action>();
        xmlNode* durationNode = FindChild(durationXml.root_, "duration");
        if (durationNode != nullptr) {
            (void)config.ParseDuration(durationNode, "duration.xml", action);
        }
        (void)config.GetXmlIntProp(durationXml.root_, "thermalLvl", INVALID_THERMAL_LVL);
    }

    XmlDocument invalidDurationXml("<act><duration>oops</duration></act>");
    if (invalidDurationXml.IsValid()) {
        auto action = std::make_shared<Action>();
        xmlNode* durationNode = FindChild(invalidDurationXml.root_, "duration");
        if (durationNode != nullptr) {
            (void)config.ParseDuration(durationNode, "duration_invalid.xml", action);
        }
    }

    XmlDocument resValueXml(
        "<act thermalLvl=\"2\" thermalCmdId=\"21003\"><cpu_max>300</cpu_max>"
        "<unknown>oops</unknown></act>");
    if (resValueXml.IsValid()) {
        auto action = std::make_shared<Action>();
        (void)config.GetXmlIntProp(resValueXml.root_, "thermalLvl", INVALID_THERMAL_LVL);
        (void)config.GetXmlIntProp(resValueXml.root_, "thermalCmdId", INVALID_THERMAL_CMD_ID);
        xmlNode* cpuMaxNode = FindChild(resValueXml.root_, "cpu_max");
        xmlNode* unknownNode = FindChild(resValueXml.root_, "unknown");
        if (cpuMaxNode != nullptr) {
            (void)config.ParseResValue(cpuMaxNode, "res_value.xml", action);
        }
        if (unknownNode != nullptr) {
            (void)config.ParseResValue(unknownNode, "res_value_invalid.xml", action);
        }
    }
}

void RunValidationCases()
{
    SocPerfConfig config;
    ResetConfig(config);
    PrimeResourceConfig(config);

    (void)config.CheckCmdTag(nullptr, "boost", "boost.xml");
    (void)config.CheckCmdTag("21000", nullptr, "boost.xml");
    (void)config.CheckCmdTag("21000", "boost", "boost.xml");

    auto validAction = std::make_shared<Action>();
    validAction->duration = 1;
    validAction->variable = {1000, 300, 1001, 100};
    auto invalidValueAction = std::make_shared<Action>();
    invalidValueAction->duration = 1;
    invalidValueAction->variable = {1000, 999};
    auto invalidResAction = std::make_shared<Action>();
    invalidResAction->duration = 1;
    invalidResAction->variable = {9999, 100};

    (void)config.TraversalActions(validAction, FUZZ_CMD_ID_WEAK_PERF);
    (void)config.TraversalActions(invalidValueAction, FUZZ_CMD_ID_WEAK_POWER);
    (void)config.TraversalActions(invalidResAction, FUZZ_CMD_ID_WEAK_THERMAL);

    auto validActions = std::make_shared<Actions>(FUZZ_CMD_ID_WEAK_PERF, "valid_actions");
    validActions->actionList.push_back(validAction);
    auto invalidActions = std::make_shared<Actions>(FUZZ_CMD_ID_WEAK_POWER, "invalid_actions");
    invalidActions->actionList.push_back(invalidResAction);

    std::unordered_map<int32_t, std::shared_ptr<Actions>> validOnlyActions;
    validOnlyActions[FUZZ_CMD_ID_WEAK_PERF] = validActions;
    (void)config.CheckActionsValid(validOnlyActions);

    config.configPerfActionsInfo_[DEFAULT_CONFIG_MODE] = validOnlyActions;
    (void)config.CheckActionResIdAndValueValid("boost_valid.xml");

    std::unordered_map<int32_t, std::shared_ptr<Actions>> actionsInfo;
    actionsInfo[FUZZ_CMD_ID_WEAK_PERF] = validActions;
    actionsInfo[FUZZ_CMD_ID_WEAK_POWER] = invalidActions;
    (void)config.CheckActionsValid(actionsInfo);

    config.configPerfActionsInfo_[DEFAULT_CONFIG_MODE] = actionsInfo;
    (void)config.CheckActionResIdAndValueValid("boost.xml");
}
} // namespace

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzDataProvider provider(data, size);
    RunBoostFileCases(provider);
    RunDirectParserCases(provider);
    RunNodeLevelCases();
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
