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
#include "socperf_thread_wrap.h"

namespace OHOS {
namespace SOCPERF {
namespace {
std::mutex g_threadWrapControlMutex;

constexpr int64_t PRIME_END_TIME_CPU_MAX = 1000;
constexpr int64_t PRIME_END_TIME_CPU_MIN = 1100;
constexpr int64_t PRIME_END_TIME_CPU_GOV = 1200;
constexpr int64_t PRIME_END_TIME_GPU_FREQ = 1300;
constexpr int32_t PRIME_END_TIME_JITTER_MAX = 10;
constexpr int64_t ASYNC_ACTION_END_TIME = 2000;
constexpr int64_t ASYNC_LEVEL_ACTION_END_TIME = 2100;
constexpr int64_t STATISTICS_TASK_DELAY_US = 500000;

struct ResActionSeed {
    int64_t value;
    int32_t duration;
    int32_t type;
    int32_t onOff;
    int32_t cmdId;
    int64_t endTime;
};

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

std::shared_ptr<ResAction> MakeResAction(const ResActionSeed& seed)
{
    return std::make_shared<ResAction>(seed.value, seed.duration, seed.type, seed.onOff,
        seed.cmdId, seed.endTime);
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

    auto cpuMax = std::make_shared<ResNode>(FUZZ_RES_ID_CPU_MAX, "cpu_max", MAX_FREQUE_NODE,
        FUZZ_RES_ID_CPU_MIN, REPORT_TO_PERFSO);
    cpuMax->def = FUZZ_FREQ_CPU_HIGH;
    cpuMax->available = {FUZZ_FREQ_CPU_LOW, FUZZ_FREQ_CPU_MID, FUZZ_FREQ_CPU_HIGH};
    cpuMax->trace = true;
    config.resourceNodeInfo_[FUZZ_RES_ID_CPU_MAX] = cpuMax;

    auto cpuMin = std::make_shared<ResNode>(FUZZ_RES_ID_CPU_MIN, "cpu_min", 0,
        FUZZ_RES_ID_CPU_MAX, WRITE_NODE);
    cpuMin->def = FUZZ_FREQ_CPU_LOW;
    cpuMin->available = {FUZZ_FREQ_CPU_LOW, FUZZ_FREQ_CPU_MID, FUZZ_FREQ_CPU_HIGH};
    config.resourceNodeInfo_[FUZZ_RES_ID_CPU_MIN] = cpuMin;

    auto cpuGov = std::make_shared<GovResNode>(FUZZ_RES_ID_CPU_GOV, "cpu_gov", REPORT_TO_PERFSO);
    cpuGov->def = 1;
    cpuGov->available = {1, FUZZ_GOV_PERFORMANCE};
    config.resourceNodeInfo_[FUZZ_RES_ID_CPU_GOV] = cpuGov;

    auto gpuFreq = std::make_shared<ResNode>(FUZZ_RES_ID_GPU_FREQ, "gpu_freq", 0,
        INVALID_VALUE, WRITE_NODE);
    gpuFreq->def = FUZZ_FREQ_GPU_MID;
    gpuFreq->available = {FUZZ_FREQ_CPU_HIGH, FUZZ_FREQ_GPU_MID, FUZZ_FREQ_GPU_HIGH};
    config.resourceNodeInfo_[FUZZ_RES_ID_GPU_FREQ] = gpuFreq;

    auto weakPerf = MakeActions(FUZZ_CMD_ID_WEAK_PERF, "weak_perf", {
        MakeActionNode(1, {FUZZ_RES_ID_CPU_MAX, FUZZ_FREQ_CPU_HIGH,
            FUZZ_RES_ID_CPU_MIN, FUZZ_FREQ_CPU_LOW}),
        MakeActionNode(0, {FUZZ_RES_ID_GPU_FREQ, FUZZ_FREQ_GPU_MID}),
    });
    auto weakPower = MakeActions(FUZZ_CMD_ID_WEAK_POWER, "weak_power", {
        MakeActionNode(1, {FUZZ_RES_ID_CPU_MAX, FUZZ_FREQ_CPU_MID,
            FUZZ_RES_ID_CPU_GOV, FUZZ_GOV_PERFORMANCE}),
    });
    auto weakThermal = MakeActions(FUZZ_CMD_ID_WEAK_THERMAL, "weak_thermal", {
        MakeActionNode(1, {FUZZ_RES_ID_CPU_MAX, FUZZ_FREQ_CPU_LOW,
            FUZZ_RES_ID_GPU_FREQ, FUZZ_FREQ_CPU_HIGH}),
    });

    auto& actionsInfo = config.configPerfActionsInfo_[DEFAULT_CONFIG_MODE];
    actionsInfo[FUZZ_CMD_ID_WEAK_PERF] = weakPerf;
    actionsInfo[FUZZ_CMD_ID_WEAK_POWER] = weakPower;
    actionsInfo[FUZZ_CMD_ID_WEAK_THERMAL] = weakThermal;

    config.interAction_.push_back(
        std::make_shared<InterAction>(FUZZ_CMD_ID_WEAK_PERF, ACTION_TYPE_PERF, 0));
    config.interAction_.push_back(
        std::make_shared<InterAction>(FUZZ_CMD_ID_WEAK_POWER, ACTION_TYPE_POWER, 0));
    config.interAction_.push_back(
        std::make_shared<InterAction>(FUZZ_CMD_ID_WEAK_THERMAL, ACTION_TYPE_THERMAL, 0));
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
    auto cpuMaxStatus = wrap.resStatusInfo_[FUZZ_RES_ID_CPU_MAX];
    cpuMaxStatus->candidate = provider.ConsumeBool() ? FUZZ_FREQ_CPU_HIGH : FUZZ_FREQ_CPU_MID;
    cpuMaxStatus->currentValue = MAX_INT32_VALUE;
    cpuMaxStatus->previousValue = NODE_DEFAULT_VALUE;
    cpuMaxStatus->currentEndTime = PRIME_END_TIME_CPU_MAX +
        provider.ConsumeInt32InRange(0, PRIME_END_TIME_JITTER_MAX);
    cpuMaxStatus->previousEndTime = MAX_INT_VALUE;

    auto cpuMinStatus = wrap.resStatusInfo_[FUZZ_RES_ID_CPU_MIN];
    cpuMinStatus->candidate = FUZZ_FREQ_CPU_LOW;
    cpuMinStatus->currentValue = FUZZ_FREQ_CPU_LOW;
    cpuMinStatus->previousValue = NODE_DEFAULT_VALUE;
    cpuMinStatus->currentEndTime = PRIME_END_TIME_CPU_MIN +
        provider.ConsumeInt32InRange(0, PRIME_END_TIME_JITTER_MAX);
    cpuMinStatus->previousEndTime = MAX_INT_VALUE;

    auto cpuGovStatus = wrap.resStatusInfo_[FUZZ_RES_ID_CPU_GOV];
    cpuGovStatus->candidate = FUZZ_GOV_PERFORMANCE;
    cpuGovStatus->currentValue = FUZZ_GOV_PERFORMANCE;
    cpuGovStatus->previousValue = NODE_DEFAULT_VALUE;
    cpuGovStatus->currentEndTime = PRIME_END_TIME_CPU_GOV +
        provider.ConsumeInt32InRange(0, PRIME_END_TIME_JITTER_MAX);
    cpuGovStatus->previousEndTime = MAX_INT_VALUE;

    auto gpuStatus = wrap.resStatusInfo_[FUZZ_RES_ID_GPU_FREQ];
    gpuStatus->candidate = FUZZ_FREQ_GPU_MID;
    gpuStatus->currentValue = FUZZ_FREQ_GPU_MID;
    gpuStatus->previousValue = NODE_DEFAULT_VALUE;
    gpuStatus->currentEndTime = PRIME_END_TIME_GPU_FREQ +
        provider.ConsumeInt32InRange(0, PRIME_END_TIME_JITTER_MAX);
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
            MakeResAction({FUZZ_FREQ_CPU_HIGH, 1, ACTION_TYPE_PERF, EVENT_ON,
                FUZZ_CMD_ID_LIMIT, ASYNC_ACTION_END_TIME}),
            FUZZ_RES_ID_CPU_MAX);
        wrap->UpdateLimitStatus(INNER_EVENT_ID_DO_FREQ_ACTION_LEVEL,
            MakeResAction({1, 1, ACTION_TYPE_PERFLVL, EVENT_ON,
                FUZZ_CMD_ID_LIMIT_LEVEL, ASYNC_LEVEL_ACTION_END_TIME}),
            RES_ID_ADDITION + FUZZ_RES_ID_CPU_MAX);
        wrap->UpdatePowerLimitBoostFreq(true);
        wrap->UpdateThermalLimitBoostFreq(true);
        wrap->ClearAllAliveRequest();
        DrainQueue(*wrap);
        wrap->SetWeakInteractionStatus(true);
        DrainQueue(*wrap);
        wrap->SetWeakInteractionStatus(false);
        DrainQueue(*wrap);

        ffrt::task_attr taskAttr;
        taskAttr.delay(STATISTICS_TASK_DELAY_US);
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

    std::vector<int32_t> perfIds = {FUZZ_RES_ID_CPU_MAX, FUZZ_RES_ID_CPU_GOV};
    std::vector<int64_t> perfValues = {FUZZ_FREQ_CPU_HIGH, FUZZ_GOV_PERFORMANCE};
    std::vector<int64_t> perfEndTimes = {MAX_INT_VALUE, MAX_INT_VALUE};
    std::vector<int32_t> rssIds = {FUZZ_RES_ID_CPU_MIN, FUZZ_RES_ID_GPU_FREQ};
    std::vector<int64_t> rssValues = {FUZZ_FREQ_CPU_LOW, FUZZ_FREQ_GPU_MID};
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
    auto weakPerfActions = config.configPerfActionsInfo_[DEFAULT_CONFIG_MODE][FUZZ_CMD_ID_WEAK_PERF];
    wrap.DoWeakInteraction(weakPerfActions, EVENT_ON, ACTION_TYPE_PERF);
    DrainQueue(wrap);

    auto perfInteraction = config.interAction_[0];
    perfInteraction->status = WEAK_INTERACTION_STATUS;
    wrap.weakInteractionStatus_ = false;
    wrap.boostResCnt = 0;
    wrap.WeakInteraction();
    DrainQueue(wrap);

    auto powerInteraction = config.interAction_[1];
    ffrt::task_attr taskAttr;
    taskAttr.delay(STATISTICS_TASK_DELAY_US);
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
