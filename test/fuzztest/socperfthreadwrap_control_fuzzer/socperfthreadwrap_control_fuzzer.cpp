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

#include "socperfthreadwrap_control_fuzzer.h"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "socperf_fuzz_permission.h"
#include "socperf_fuzz_utils.h"

#define private public
#define protected public
#include "socperf_thread_wrap.h"
#undef private
#undef protected

namespace OHOS {
namespace SOCPERF {
namespace {
std::mutex g_threadWrapControlMutex;

constexpr int32_t RES_CPU_MAX = 1000;
constexpr int32_t RES_CPU_MIN = 1001;
constexpr int32_t RES_CPU_GOV = 1002;
constexpr int32_t RES_GPU_FREQ = 1003;
constexpr int32_t CMD_WEAK_PERF = 21000;
constexpr int32_t CMD_WEAK_POWER = 21001;
constexpr int32_t CMD_WEAK_THERMAL = 21002;

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

std::shared_ptr<Action> MakeActionNode(int32_t duration, const std::vector<int64_t>& values)
{
    auto action = std::make_shared<Action>();
    action->duration = duration;
    action->variable = values;
    return action;
}

std::shared_ptr<Actions> MakeActions(int32_t cmdId, const std::string& name,
    const std::vector<std::shared_ptr<Action>>& actionList)
{
    auto actions = std::make_shared<Actions>(cmdId, name);
    for (const auto& action : actionList) {
        actions->actionList.push_back(action);
    }
    return actions;
}

std::shared_ptr<ResAction> MakeResAction(int64_t value, int32_t duration, int32_t type, int32_t onOff,
    int32_t cmdId, int64_t endTime)
{
    return std::make_shared<ResAction>(value, duration, type, onOff, cmdId, endTime);
}

void DrainQueue(SocPerfThreadWrap& wrap)
{
    ffrt::task_handle barrier = wrap.socperfQueue_.submit_h([]() {});
    wrap.socperfQueue_.wait(barrier);
}

void SeedControlConfig()
{
    ResetConfig();
    auto& config = SocPerfConfig::GetInstance();

    auto cpuMax = std::make_shared<ResNode>(RES_CPU_MAX, "cpu_max", MAX_FREQUE_NODE, RES_CPU_MIN, REPORT_TO_PERFSO);
    cpuMax->def = 300;
    cpuMax->available = {100, 200, 300};
    cpuMax->trace = true;
    config.resourceNodeInfo_[RES_CPU_MAX] = cpuMax;

    auto cpuMin = std::make_shared<ResNode>(RES_CPU_MIN, "cpu_min", 0, RES_CPU_MAX, WRITE_NODE);
    cpuMin->def = 100;
    cpuMin->available = {100, 200, 300};
    config.resourceNodeInfo_[RES_CPU_MIN] = cpuMin;

    auto cpuGov = std::make_shared<GovResNode>(RES_CPU_GOV, "cpu_gov", REPORT_TO_PERFSO);
    cpuGov->def = 1;
    cpuGov->available = {1, 2};
    config.resourceNodeInfo_[RES_CPU_GOV] = cpuGov;

    auto gpuFreq = std::make_shared<ResNode>(RES_GPU_FREQ, "gpu_freq", 0, INVALID_VALUE, WRITE_NODE);
    gpuFreq->def = 400;
    gpuFreq->available = {300, 400, 500};
    config.resourceNodeInfo_[RES_GPU_FREQ] = gpuFreq;

    auto weakPerf = MakeActions(CMD_WEAK_PERF, "weak_perf", {
        MakeActionNode(1, {RES_CPU_MAX, 300, RES_CPU_MIN, 100}),
        MakeActionNode(0, {RES_GPU_FREQ, 400}),
    });
    auto weakPower = MakeActions(CMD_WEAK_POWER, "weak_power", {
        MakeActionNode(1, {RES_CPU_MAX, 200, RES_CPU_GOV, 2}),
    });
    auto weakThermal = MakeActions(CMD_WEAK_THERMAL, "weak_thermal", {
        MakeActionNode(1, {RES_CPU_MAX, 100, RES_GPU_FREQ, 300}),
    });

    auto& actionsInfo = config.configPerfActionsInfo_[DEFAULT_CONFIG_MODE];
    actionsInfo[CMD_WEAK_PERF] = weakPerf;
    actionsInfo[CMD_WEAK_POWER] = weakPower;
    actionsInfo[CMD_WEAK_THERMAL] = weakThermal;

    config.interAction_.push_back(std::make_shared<InterAction>(CMD_WEAK_PERF, ACTION_TYPE_PERF, 0));
    config.interAction_.push_back(std::make_shared<InterAction>(CMD_WEAK_POWER, ACTION_TYPE_POWER, 0));
    config.interAction_.push_back(std::make_shared<InterAction>(CMD_WEAK_THERMAL, ACTION_TYPE_THERMAL, 0));
}

void PrepareWrap(SocPerfThreadWrap& wrap, bool fillStatus)
{
    wrap.resStatusInfo_.clear();
    wrap.powerLimitBoost_ = false;
    wrap.thermalLimitBoost_ = false;
    wrap.weakInteractionStatus_ = true;
    wrap.boostResCnt = 0;
    wrap.thermalLvl_ = 0;
    if (!fillStatus) {
        return;
    }
    for (const auto& item : SocPerfConfig::GetInstance().resourceNodeInfo_) {
        wrap.resStatusInfo_[item.first] = std::make_shared<ResStatus>();
    }
}

void PrimeReportStatus(SocPerfThreadWrap& wrap, FuzzDataProvider& provider)
{
    auto cpuMaxStatus = wrap.resStatusInfo_[RES_CPU_MAX];
    cpuMaxStatus->candidate = provider.ConsumeBool() ? 300 : 200;
    cpuMaxStatus->currentValue = MAX_INT32_VALUE;
    cpuMaxStatus->previousValue = NODE_DEFAULT_VALUE;
    cpuMaxStatus->currentEndTime = 1000 + provider.ConsumeInt32InRange(0, 10);
    cpuMaxStatus->previousEndTime = MAX_INT_VALUE;

    auto cpuMinStatus = wrap.resStatusInfo_[RES_CPU_MIN];
    cpuMinStatus->candidate = 100;
    cpuMinStatus->currentValue = 100;
    cpuMinStatus->previousValue = NODE_DEFAULT_VALUE;
    cpuMinStatus->currentEndTime = 1100 + provider.ConsumeInt32InRange(0, 10);
    cpuMinStatus->previousEndTime = MAX_INT_VALUE;

    auto cpuGovStatus = wrap.resStatusInfo_[RES_CPU_GOV];
    cpuGovStatus->candidate = 2;
    cpuGovStatus->currentValue = 2;
    cpuGovStatus->previousValue = NODE_DEFAULT_VALUE;
    cpuGovStatus->currentEndTime = 1200 + provider.ConsumeInt32InRange(0, 10);
    cpuGovStatus->previousEndTime = MAX_INT_VALUE;

    auto gpuStatus = wrap.resStatusInfo_[RES_GPU_FREQ];
    gpuStatus->candidate = 400;
    gpuStatus->currentValue = 400;
    gpuStatus->previousValue = NODE_DEFAULT_VALUE;
    gpuStatus->currentEndTime = 1300 + provider.ConsumeInt32InRange(0, 10);
    gpuStatus->previousEndTime = MAX_INT_VALUE;
}

void RunAsyncCoverageOnce()
{
    static std::once_flag once;
    std::call_once(once, []() {
        SeedControlConfig();
        static auto* wrap = new SocPerfThreadWrap();
        PrepareWrap(*wrap, false);
        wrap->InitResourceNodeInfo();
        DrainQueue(*wrap);

        wrap->UpdateLimitStatus(INNER_EVENT_ID_DO_FREQ_ACTION,
            MakeResAction(300, 1, ACTION_TYPE_PERF, EVENT_ON, 30000, 2000), RES_CPU_MAX);
        wrap->UpdateLimitStatus(INNER_EVENT_ID_DO_FREQ_ACTION_LEVEL,
            MakeResAction(1, 1, ACTION_TYPE_PERFLVL, EVENT_ON, 30001, 2100), RES_ID_ADDITION + RES_CPU_MAX);
        wrap->UpdatePowerLimitBoostFreq(true);
        wrap->UpdateThermalLimitBoostFreq(true);
        wrap->ClearAllAliveRequest();
        DrainQueue(*wrap);
        wrap->SetWeakInteractionStatus(true);
        DrainQueue(*wrap);
        wrap->SetWeakInteractionStatus(false);
        DrainQueue(*wrap);

        ffrt::task_attr taskAttr;
        taskAttr.delay(500000);
        ffrt::task_handle timer = nullptr;
        wrap->SubmitStatisticsTask([]() {}, taskAttr, timer);
        wrap->CancelStatisticsTask(timer);
    });
}

void RunDirectCoverage(FuzzDataProvider& provider)
{
    SeedControlConfig();
    SocPerfThreadWrap wrap;
    PrepareWrap(wrap, true);
    auto& config = SocPerfConfig::GetInstance();

    std::vector<int32_t> perfIds = {RES_CPU_MAX, RES_CPU_GOV};
    std::vector<int64_t> perfValues = {300, 2};
    std::vector<int64_t> perfEndTimes = {MAX_INT_VALUE, MAX_INT_VALUE};
    std::vector<int32_t> rssIds = {RES_CPU_MIN, RES_GPU_FREQ};
    std::vector<int64_t> rssValues = {100, 400};
    std::vector<int64_t> rssEndTimes = {MAX_INT_VALUE, MAX_INT_VALUE};
    std::vector<int32_t> emptyIds;
    std::vector<int64_t> emptyValues;
    std::vector<int64_t> emptyEndTimes;

    config.reportFunc_ = nullptr;
    wrap.ReportToPerfSo(perfIds, perfValues, perfEndTimes);
    config.reportFunc_ = ReportDataStub;
    wrap.ReportToPerfSo(emptyIds, emptyValues, emptyEndTimes);
    wrap.ReportToPerfSo(perfIds, perfValues, perfEndTimes);
    wrap.ReportToRssExe(emptyIds, emptyValues, emptyEndTimes);
    wrap.ReportToRssExe(rssIds, rssValues, rssEndTimes);

    wrap.InitResStatus();

    wrap.DoWeakInteraction(nullptr, EVENT_ON, ACTION_TYPE_PERF);
    wrap.DoWeakInteraction(config.configPerfActionsInfo_[DEFAULT_CONFIG_MODE][CMD_WEAK_PERF], EVENT_ON, ACTION_TYPE_PERF);
    DrainQueue(wrap);

    auto perfInteraction = config.interAction_[0];
    perfInteraction->status = WEAK_INTERACTION_STATUS;
    wrap.weakInteractionStatus_ = false;
    wrap.boostResCnt = 0;
    wrap.WeakInteraction();
    DrainQueue(wrap);

    auto powerInteraction = config.interAction_[1];
    ffrt::task_attr taskAttr;
    taskAttr.delay(500000);
    wrap.SubmitStatisticsTask([]() {}, taskAttr, powerInteraction->timerTask);
    powerInteraction->status = BOOST_END_STATUS;
    wrap.weakInteractionStatus_ = false;
    wrap.boostResCnt = 1;
    wrap.WeakInteraction();

    PrimeReportStatus(wrap, provider);
    wrap.SendResStatus();
    DrainQueue(wrap);

    ffrt::task_handle localTimer = nullptr;
    wrap.SubmitStatisticsTask([]() {}, taskAttr, localTimer);
    wrap.CancelStatisticsTask(localTimer);
    wrap.CancelStatisticsTask(localTimer);
}
} // namespace

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::lock_guard<std::mutex> lock(g_threadWrapControlMutex);
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
