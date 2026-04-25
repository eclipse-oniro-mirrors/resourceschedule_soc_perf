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

#include "socperfcore_request_fuzzer.h"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "socperf_fuzz_mock.h"
#include "socperf_fuzz_utils.h"

#define private public
#define protected public
#include "socperf.h"
#undef private
#undef protected

namespace OHOS {
namespace SOCPERF {
namespace {
std::mutex g_coreMutex;

constexpr int32_t EVENT_FLING = 10008;
constexpr int32_t EVENT_TOUCH_DOWN = 10010;
constexpr int32_t EVENT_TOUCH_UP = 10040;
constexpr int32_t EVENT_DRAG = 10092;
constexpr int32_t CMD_PERF = 20000;
constexpr int32_t CMD_LONG_PERF = 20001;
constexpr int32_t CMD_THERMAL_PERF = 20002;
constexpr int32_t CMD_THERMAL_LEVEL = 30000;

int ReportDataStub(const std::vector<int32_t>&, const std::vector<int64_t>&,
    const std::vector<int64_t>&, const std::string&)
{
    return 0;
}

void ResetConfig()
{
    auto& config = SocPerfConfig::GetInstance();
    config.resourceNodeInfo_.clear();
    config.sceneResourceInfo_.clear();
    config.configPerfActionsInfo_.clear();
    config.interAction_.clear();
    config.reportFunc_ = ReportDataStub;
    config.scenarioFunc_ = nullptr;
    config.minThermalLvl_ = 0;
}

std::shared_ptr<Action> MakeAction(int32_t duration, const std::vector<int64_t>& values,
    int32_t thermalCmdId = INVALID_THERMAL_CMD_ID, int32_t thermalLvl = INVALID_THERMAL_LVL)
{
    auto action = std::make_shared<Action>();
    action->duration = duration;
    action->variable = values;
    action->thermalCmdId_ = thermalCmdId;
    action->thermalLvl_ = thermalLvl;
    return action;
}

std::shared_ptr<Actions> MakeActions(int32_t cmdId, const std::string& name,
    const std::vector<std::shared_ptr<Action>>& actionList, bool longTimePerf = false)
{
    auto actions = std::make_shared<Actions>(cmdId, name);
    for (const auto& action : actionList) {
        actions->actionList.push_back(action);
    }
    actions->isLongTimePerf = longTimePerf;
    return actions;
}

void SeedCoreConfig()
{
    ResetConfig();
    auto& config = SocPerfConfig::GetInstance();

    auto maxRes = std::make_shared<ResNode>(1000, "cpu_max", MAX_FREQUE_NODE, 1001, REPORT_TO_PERFSO);
    maxRes->def = 300;
    maxRes->available = {100, 200, 300};
    config.resourceNodeInfo_[1000] = maxRes;

    auto minRes = std::make_shared<ResNode>(1001, "cpu_min", 0, 1000, REPORT_TO_PERFSO);
    minRes->def = 100;
    minRes->available = {100, 200, 300};
    config.resourceNodeInfo_[1001] = minRes;

    auto gpuRes = std::make_shared<ResNode>(1003, "gpu_freq", 0, INVALID_VALUE, REPORT_TO_PERFSO);
    gpuRes->def = 400;
    gpuRes->available = {300, 400, 500};
    config.resourceNodeInfo_[1003] = gpuRes;

    auto touchAction = MakeAction(1, {1000, 300, 1001, 100});
    auto flingAction = MakeAction(1, {1000, 250, 1003, 400});
    auto perfAction = MakeAction(1, {1000, 280, 1001, 120});
    auto longPerfAction = MakeAction(0, {1000, 220, 1003, 500});
    auto thermalPerfAction = MakeAction(1, {1000, 260}, CMD_THERMAL_LEVEL);
    auto thermalLevelAction = MakeAction(1, {1000, 180, 1001, 100}, INVALID_THERMAL_CMD_ID, 0);

    std::unordered_map<int32_t, std::shared_ptr<Actions>> defaultActions;
    defaultActions[EVENT_TOUCH_DOWN] = MakeActions(EVENT_TOUCH_DOWN, "touch_down", {touchAction});
    defaultActions[EVENT_FLING] = MakeActions(EVENT_FLING, "fling", {flingAction});
    defaultActions[CMD_PERF] = MakeActions(CMD_PERF, "perf_request", {perfAction});
    defaultActions[CMD_LONG_PERF] = MakeActions(CMD_LONG_PERF, "perf_request_ex", {longPerfAction}, true);
    defaultActions[CMD_THERMAL_PERF] = MakeActions(CMD_THERMAL_PERF, "thermal_perf", {thermalPerfAction});
    defaultActions[CMD_THERMAL_LEVEL] = MakeActions(CMD_THERMAL_LEVEL, "thermal_level", {thermalLevelAction});
    config.configPerfActionsInfo_[DEFAULT_CONFIG_MODE] = defaultActions;
}

void PrepareWrap(SocPerfThreadWrap& wrap)
{
    wrap.resStatusInfo_.clear();
    wrap.powerLimitBoost_ = false;
    wrap.thermalLimitBoost_ = false;
    wrap.boostResCnt = 0;
    wrap.thermalLvl_ = 0;
    for (const auto& item : SocPerfConfig::GetInstance().resourceNodeInfo_) {
        wrap.resStatusInfo_[item.first] = std::make_shared<ResStatus>();
    }
}

std::shared_ptr<SocPerfThreadWrap> MakeNonOwningWrap(SocPerfThreadWrap* wrap)
{
    return std::shared_ptr<SocPerfThreadWrap>(wrap, [](SocPerfThreadWrap*) {});
}

void RunAsyncCoverageOnce()
{
    static std::once_flag once;
    std::call_once(once, []() {
        auto* initCore = new SocPerf();
        (void)initCore->Init();
        initCore->StopStatisticsTimer();

        SeedCoreConfig();
        (void)initCore->CreateThreadWraps();
        if (initCore->socperfThreadWrap_ != nullptr) {
            PrepareWrap(*initCore->socperfThreadWrap_);
        }
        initCore->InitThreadWraps();
        initCore->CompleteEvent();
        initCore->StartStatisticsTimer();
        initCore->StopStatisticsTimer();

        SeedCoreConfig();
        static auto* requestWrap = new SocPerfThreadWrap();
        PrepareWrap(*requestWrap);
        auto* requestCore = new SocPerf();
        requestCore->enabled_ = true;
        requestCore->perfRequestEnable_ = true;
        requestCore->thermalLvl_ = 1;
        requestCore->socperfThreadWrap_ = MakeNonOwningWrap(requestWrap);
        requestCore->CompleteEvent();
        requestCore->PerfRequest(CMD_PERF, "async_perf");
        requestCore->PerfRequestEx(CMD_LONG_PERF, true, "async_on");
        requestCore->PerfRequestEx(CMD_LONG_PERF, false, "async_off");
        requestCore->DoFreqActions(requestCore->GetActionsInfo(CMD_THERMAL_PERF), EVENT_INVALID, ACTION_TYPE_PERF);
    });
}

void RunDirectCoverage(FuzzDataProvider& provider)
{
    SeedCoreConfig();
    SocPerf core;
    core.enabled_ = true;
    core.perfRequestEnable_ = true;
    core.thermalLvl_ = provider.ConsumeBool() ? 1 : 0;

    auto& perfActionsInfo = SocPerfConfig::GetInstance().configPerfActionsInfo_[DEFAULT_CONFIG_MODE];
    (void)core.CompleteEvent();
    core.CopyEvent(EVENT_TOUCH_DOWN, 10050, perfActionsInfo);
    core.CopyEvent(99999, EVENT_TOUCH_UP, perfActionsInfo);

    auto originAction = std::make_shared<Action>();
    originAction->duration = 1;
    originAction->thermalCmdId_ = CMD_THERMAL_LEVEL;
    originAction->variable = {1000, 260};
    auto head = std::make_shared<ResActionItem>(1000);
    (void)core.DoPerfRequestThremalLvl(CMD_THERMAL_PERF, originAction, EVENT_INVALID, nullptr, 1000);
    (void)core.DoPerfRequestThremalLvl(CMD_THERMAL_PERF, originAction, EVENT_INVALID, head, 1000);

    (void)core.GetActionsInfo(CMD_PERF);
    core.UpdateCmdIdCount(CMD_PERF);
    core.UpdateCmdIdCount(CMD_PERF);
    (void)core.RequestCmdIdCount(provider.ConsumeString(32));

    (void)core.CheckTimeInterval(true, CMD_PERF);
    (void)core.CheckTimeInterval(true, CMD_PERF);
    (void)core.CheckTimeInterval(false, CMD_PERF);

    core.UpdateDailyCmdIdCount(CMD_PERF);
    core.UpdateDailyCmdIdCount(CMD_LONG_PERF);
    core.ReportCmdIdStatistics();
    core.ReportCmdIdStatistics();
}
} // namespace

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::lock_guard<std::mutex> lock(g_coreMutex);
    FuzzDataProvider provider(data, size);
    RunAsyncCoverageOnce();
    RunDirectCoverage(provider);
    return true;
}
} // namespace SOCPERF
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SOCPERF::MockProcess();
    OHOS::SOCPERF::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
