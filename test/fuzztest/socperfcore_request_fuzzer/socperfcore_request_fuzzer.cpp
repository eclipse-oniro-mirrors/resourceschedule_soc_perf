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

#include "socperf_fuzz_permission.h"
#include "socperf_fuzz_utils.h"
#include "socperf.h"

namespace OHOS {
namespace SOCPERF {
namespace {
std::mutex g_coreMutex;

constexpr int32_t EVENT_FLING = 10008;
constexpr int32_t EVENT_TOUCH_DOWN = 10010;
constexpr int32_t EVENT_TOUCH_UP = 10040;
constexpr int32_t EVENT_DRAG = 10092;
constexpr int32_t FUZZ_COPY_EVENT_ID = 10050;
constexpr int32_t FUZZ_UNKNOWN_EVENT_ID = 99999;

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

    auto maxRes = std::make_shared<ResNode>(FUZZ_RES_ID_CPU_MAX, "cpu_max", MAX_FREQUE_NODE,
        FUZZ_RES_ID_CPU_MIN, REPORT_TO_PERFSO);
    maxRes->def = FUZZ_FREQ_CPU_HIGH;
    maxRes->available = {FUZZ_FREQ_CPU_LOW, FUZZ_FREQ_CPU_MID, FUZZ_FREQ_CPU_HIGH};
    config.resourceNodeInfo_[FUZZ_RES_ID_CPU_MAX] = maxRes;

    auto minRes = std::make_shared<ResNode>(FUZZ_RES_ID_CPU_MIN, "cpu_min", 0,
        FUZZ_RES_ID_CPU_MAX, REPORT_TO_PERFSO);
    minRes->def = FUZZ_FREQ_CPU_LOW;
    minRes->available = {FUZZ_FREQ_CPU_LOW, FUZZ_FREQ_CPU_MID, FUZZ_FREQ_CPU_HIGH};
    config.resourceNodeInfo_[FUZZ_RES_ID_CPU_MIN] = minRes;

    auto gpuRes = std::make_shared<ResNode>(FUZZ_RES_ID_GPU_FREQ, "gpu_freq", 0,
        INVALID_VALUE, REPORT_TO_PERFSO);
    gpuRes->def = FUZZ_FREQ_GPU_MID;
    gpuRes->available = {FUZZ_FREQ_CPU_HIGH, FUZZ_FREQ_GPU_MID, FUZZ_FREQ_GPU_HIGH};
    config.resourceNodeInfo_[FUZZ_RES_ID_GPU_FREQ] = gpuRes;

    auto touchAction = MakeAction(1, {FUZZ_RES_ID_CPU_MAX, FUZZ_FREQ_CPU_HIGH,
        FUZZ_RES_ID_CPU_MIN, FUZZ_FREQ_CPU_LOW});
    auto flingAction = MakeAction(1, {FUZZ_RES_ID_CPU_MAX, 250, FUZZ_RES_ID_GPU_FREQ,
        FUZZ_FREQ_GPU_MID});
    auto perfAction = MakeAction(1, {FUZZ_RES_ID_CPU_MAX, 280, FUZZ_RES_ID_CPU_MIN, 120});
    auto longPerfAction = MakeAction(0, {FUZZ_RES_ID_CPU_MAX, 220, FUZZ_RES_ID_GPU_FREQ, 500});
    auto thermalPerfAction = MakeAction(1, {FUZZ_RES_ID_CPU_MAX, 260}, FUZZ_CMD_ID_LIMIT);
    auto thermalLevelAction = MakeAction(1, {FUZZ_RES_ID_CPU_MAX, 180, FUZZ_RES_ID_CPU_MIN,
        FUZZ_FREQ_CPU_LOW}, INVALID_THERMAL_CMD_ID, 0);

    std::unordered_map<int32_t, std::shared_ptr<Actions>> defaultActions;
    defaultActions[EVENT_TOUCH_DOWN] = MakeActions(EVENT_TOUCH_DOWN, "touch_down", {touchAction});
    defaultActions[EVENT_FLING] = MakeActions(EVENT_FLING, "fling", {flingAction});
    defaultActions[FUZZ_CMD_ID_PERF] = MakeActions(FUZZ_CMD_ID_PERF, "perf_request", {perfAction});
    defaultActions[FUZZ_CMD_ID_LONG_PERF] = MakeActions(FUZZ_CMD_ID_LONG_PERF, "perf_request_ex",
        {longPerfAction}, true);
    defaultActions[FUZZ_CMD_ID_THERMAL_PERF] = MakeActions(FUZZ_CMD_ID_THERMAL_PERF, "thermal_perf",
        {thermalPerfAction});
    defaultActions[FUZZ_CMD_ID_LIMIT] = MakeActions(FUZZ_CMD_ID_LIMIT, "thermal_level",
        {thermalLevelAction});
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

void DrainQueue(SocPerfThreadWrap& wrap)
{
    ffrt::task_handle barrier = wrap.socperfQueue_.submit_h([]() {});
    wrap.socperfQueue_.wait(barrier);
}

void RunAsyncCoverageOnce()
{
    static std::once_flag once;
    std::call_once(once, []() {
        SeedCoreConfig();
        auto* initCore = new SocPerf();
        (void)initCore->CreateThreadWraps();
        if (initCore->socperfThreadWrap_ != nullptr) {
            PrepareWrap(*initCore->socperfThreadWrap_);
            initCore->InitThreadWraps();
            DrainQueue(*initCore->socperfThreadWrap_);
        }
        initCore->enabled_ = true;
        initCore->perfRequestEnable_ = true;
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
        requestCore->PerfRequest(FUZZ_CMD_ID_PERF, "async_perf");
        requestCore->PerfRequestEx(FUZZ_CMD_ID_LONG_PERF, true, "async_on");
        requestCore->PerfRequestEx(FUZZ_CMD_ID_LONG_PERF, false, "async_off");
        requestCore->DoFreqActions(requestCore->GetActionsInfo(FUZZ_CMD_ID_THERMAL_PERF),
            EVENT_INVALID, ACTION_TYPE_PERF);
        DrainQueue(*requestWrap);
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
    core.CopyEvent(EVENT_TOUCH_DOWN, FUZZ_COPY_EVENT_ID, perfActionsInfo);
    core.CopyEvent(FUZZ_UNKNOWN_EVENT_ID, EVENT_TOUCH_UP, perfActionsInfo);

    auto originAction = std::make_shared<Action>();
    originAction->duration = 1;
    originAction->thermalCmdId_ = FUZZ_CMD_ID_LIMIT;
    originAction->variable = {FUZZ_RES_ID_CPU_MAX, 260};
    auto head = std::make_shared<ResActionItem>(FUZZ_RES_ID_CPU_MAX);
    (void)core.DoPerfRequestThremalLvl(FUZZ_CMD_ID_THERMAL_PERF, originAction, EVENT_INVALID,
        nullptr, FUZZ_RES_ID_CPU_MAX);
    (void)core.DoPerfRequestThremalLvl(FUZZ_CMD_ID_THERMAL_PERF, originAction, EVENT_INVALID,
        head, FUZZ_RES_ID_CPU_MAX);

    (void)core.GetActionsInfo(FUZZ_CMD_ID_PERF);
    core.UpdateCmdIdCount(FUZZ_CMD_ID_PERF);
    core.UpdateCmdIdCount(FUZZ_CMD_ID_PERF);
    (void)core.RequestCmdIdCount(provider.ConsumeString(FUZZ_RANDOM_TEXT_MAX_LEN));

    (void)core.CheckTimeInterval(true, FUZZ_CMD_ID_PERF);
    (void)core.CheckTimeInterval(true, FUZZ_CMD_ID_PERF);
    (void)core.CheckTimeInterval(false, FUZZ_CMD_ID_PERF);

    core.UpdateDailyCmdIdCount(FUZZ_CMD_ID_PERF);
    core.UpdateDailyCmdIdCount(FUZZ_CMD_ID_LONG_PERF);
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
