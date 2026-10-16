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

#include "socperfcore_limit_fuzzer.h"

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
std::mutex g_coreLimitMutex;

constexpr int64_t ALIVE_ACTION_END_TIME = 3000;
constexpr int32_t FUZZ_THERMAL_LEVEL_MID = 2;
constexpr int32_t FUZZ_THERMAL_LEVEL_HIGH = 4;
constexpr int64_t FUZZ_BATTERY_LIMIT_VALUE = 220;
constexpr size_t FUZZ_POWER_MSG_MAX_LEN = 24;

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

void SeedLimitConfig()
{
    ResetConfig();
    auto& config = SocPerfConfig::GetInstance();

    auto cpuMax = std::make_shared<ResNode>(FUZZ_RES_ID_CPU_MAX, "cpu_max", MAX_FREQUE_NODE,
        FUZZ_RES_ID_CPU_MIN, REPORT_TO_PERFSO);
    cpuMax->def = FUZZ_FREQ_CPU_HIGH;
    cpuMax->available = {FUZZ_FREQ_CPU_LOW, FUZZ_FREQ_CPU_MID, FUZZ_FREQ_CPU_HIGH};
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
}

void PrepareWrap(SocPerfThreadWrap& wrap)
{
    wrap.resStatusInfo_.clear();
    wrap.powerLimitBoost_ = false;
    wrap.thermalLimitBoost_ = false;
    wrap.weakInteractionStatus_ = true;
    wrap.boostResCnt = 0;
    wrap.thermalLvl_ = 0;
    for (const auto& item : SocPerfConfig::GetInstance().resourceNodeInfo_) {
        wrap.resStatusInfo_[item.first] = std::make_shared<ResStatus>();
    }
}

void SeedAlivePerfRequests(SocPerfThreadWrap& wrap)
{
    auto cpuMaxStatus = wrap.resStatusInfo_[FUZZ_RES_ID_CPU_MAX];
    auto cpuMinStatus = wrap.resStatusInfo_[FUZZ_RES_ID_CPU_MIN];
    if (cpuMaxStatus == nullptr || cpuMinStatus == nullptr) {
        return;
    }
    cpuMaxStatus->resActionList[ACTION_TYPE_PERF].push_back(
        MakeResAction({FUZZ_FREQ_CPU_HIGH, 1, ACTION_TYPE_PERF, EVENT_ON,
            FUZZ_CMD_ID_ALIVE_PERF, ALIVE_ACTION_END_TIME}));
    cpuMinStatus->resActionList[ACTION_TYPE_PERF].push_back(
        MakeResAction({FUZZ_FREQ_CPU_LOW, 1, ACTION_TYPE_PERF, EVENT_ON,
            FUZZ_CMD_ID_ALIVE_PERF, ALIVE_ACTION_END_TIME}));
    wrap.UpdateCandidatesValue(FUZZ_RES_ID_CPU_MAX, ACTION_TYPE_PERF);
    wrap.UpdateCandidatesValue(FUZZ_RES_ID_CPU_MIN, ACTION_TYPE_PERF);
}

std::shared_ptr<SocPerfThreadWrap> MakeNonOwningWrap(SocPerfThreadWrap* wrap)
{
    return std::shared_ptr<SocPerfThreadWrap>(wrap, [](SocPerfThreadWrap*) {});
}

void RunAsyncCoverageOnce()
{
    static std::once_flag once;
    std::call_once(once, []() {
        SeedLimitConfig();
        static auto* wrap = new SocPerfThreadWrap();
        PrepareWrap(*wrap);
        SeedAlivePerfRequests(*wrap);

        auto* core = new SocPerf();
        core->enabled_ = true;
        core->perfRequestEnable_ = true;
        core->socperfThreadWrap_ = MakeNonOwningWrap(wrap);

        core->PowerLimitBoost(true, "Low_battery_limit");
        core->PowerLimitBoost(true, "power_limit");
        core->PowerLimitBoost(false, "power_limit");
        core->ThermalLimitBoost(true, "thermal_limit");
        core->ThermalLimitBoost(false, "thermal_limit");
        core->SetRequestStatus(false, "async_disable");
        core->SetRequestStatus(true, "async_enable");
        core->SetThermalLevel(1);
        core->LimitRequest(ACTION_TYPE_POWER,
            std::vector<int32_t> {FUZZ_RES_ID_CPU_MAX, RES_ID_ADDITION + FUZZ_RES_ID_CPU_MAX},
            std::vector<int64_t> {FUZZ_FREQ_CPU_MID, 1}, "async_power");
        core->LimitRequest(ACTION_TYPE_BATTERY, std::vector<int32_t> {FUZZ_RES_ID_CPU_MIN},
            std::vector<int64_t> {FUZZ_FREQ_CPU_LOW}, "async_battery");
        DrainQueue(*wrap);
    });
}

void PrimeDirectedCore(SocPerf& core, SocPerfThreadWrap& wrap, FuzzDataProvider& provider)
{
    core.enabled_ = true;
    core.perfRequestEnable_ = true;
    core.thermalLvl_ = provider.ConsumeInt32InRange(0, FUZZ_THERMAL_LEVEL_MID);
    core.socperfThreadWrap_ = MakeNonOwningWrap(&wrap);
    wrap.thermalLvl_ = core.thermalLvl_;

    core.enabled_ = false;
    core.PowerLimitBoost(true, "disabled_power");
    core.ThermalLimitBoost(true, "disabled_thermal");
    core.LimitRequest(ACTION_TYPE_POWER, std::vector<int32_t> {FUZZ_RES_ID_CPU_MAX},
        std::vector<int64_t> {FUZZ_FREQ_CPU_MID}, "disabled");
    core.ClearAllAliveRequest();
    core.SetThermalLevel(FUZZ_THERMAL_LEVEL_MID);

    core.enabled_ = true;
    core.PowerLimitBoost(true, "Low_battery_limit");
    core.PowerLimitBoost(false, "power_limit");
    std::string powerMsg = provider.ConsumeString(FUZZ_POWER_MSG_MAX_LEN);
    if (powerMsg.empty() || powerMsg == "Low_battery_limit") {
        powerMsg = "power_limit_fuzz";
    }
    core.PowerLimitBoost(provider.ConsumeBool(), powerMsg);
    core.ThermalLimitBoost(true, "thermal_msg");
    core.ThermalLimitBoost(false, "thermal_msg");
    core.SetThermalLevel(provider.ConsumeInt32InRange(0, FUZZ_THERMAL_LEVEL_HIGH));
}

void RunLimitEventCases(SocPerf& core, FuzzDataProvider& provider)
{
    core.SendLimitRequestEventOn(ACTION_TYPE_POWER, FUZZ_RES_ID_CPU_MAX,
        provider.ConsumeInt32InRange(FUZZ_FREQ_CPU_LOW, FUZZ_FREQ_CPU_HIGH),
        INNER_EVENT_ID_DO_FREQ_ACTION);
    core.SendLimitRequestEventOn(ACTION_TYPE_BATTERY, FUZZ_RES_ID_CPU_MIN, FUZZ_FREQ_CPU_LOW,
        INNER_EVENT_ID_DO_FREQ_ACTION);
    core.SendLimitRequestEventOn(ACTION_TYPE_THERMAL, RES_ID_ADDITION + FUZZ_RES_ID_CPU_MAX,
        provider.ConsumeInt32InRange(0, FUZZ_THERMAL_LEVEL_MID),
        INNER_EVENT_ID_DO_FREQ_ACTION_LEVEL);
    core.SendLimitRequestEventOn(ACTION_TYPE_POWER, FUZZ_RES_ID_CPU_MAX, INVALID_VALUE,
        INNER_EVENT_ID_DO_FREQ_ACTION);
    core.SendLimitRequestEventOn(ACTION_TYPE_POWER, FUZZ_RES_ID_CPU_MAX, RESET_VALUE,
        INNER_EVENT_ID_DO_FREQ_ACTION);

    core.limitRequest_[ACTION_TYPE_THERMAL][FUZZ_RES_ID_GPU_FREQ] = INVALID_VALUE;
    core.SendLimitRequestEventOff(ACTION_TYPE_THERMAL, FUZZ_RES_ID_GPU_FREQ,
        INNER_EVENT_ID_DO_FREQ_ACTION);
    core.SendLimitRequestEventOff(ACTION_TYPE_POWER, FUZZ_RES_ID_CPU_MAX,
        INNER_EVENT_ID_DO_FREQ_ACTION);
    core.SendLimitRequestEventOff(ACTION_TYPE_BATTERY, FUZZ_RES_ID_CPU_MIN,
        INNER_EVENT_ID_DO_FREQ_ACTION);
    core.SendLimitRequestEventOff(ACTION_TYPE_THERMAL, RES_ID_ADDITION + FUZZ_RES_ID_CPU_MAX,
        INNER_EVENT_ID_DO_FREQ_ACTION_LEVEL);

    core.SendLimitRequestEvent(ACTION_TYPE_POWER, FUZZ_RES_ID_UNKNOWN, FUZZ_FREQ_CPU_MID);
    core.SendLimitRequestEvent(ACTION_TYPE_POWER, FUZZ_RES_ID_CPU_MAX,
        provider.ConsumeInt32InRange(FUZZ_FREQ_CPU_LOW, FUZZ_FREQ_CPU_HIGH));
    core.SendLimitRequestEvent(ACTION_TYPE_THERMAL, RES_ID_ADDITION + FUZZ_RES_ID_CPU_MAX,
        provider.ConsumeInt32InRange(0, FUZZ_THERMAL_LEVEL_MID));
    core.SendLimitRequestEvent(ACTION_TYPE_BATTERY, FUZZ_RES_ID_CPU_MIN,
        provider.ConsumeBool() ? INVALID_VALUE :
            provider.ConsumeInt32InRange(FUZZ_FREQ_CPU_LOW, FUZZ_FREQ_CPU_MID));
}

void RunLimitRequestCases(SocPerf& core, FuzzDataProvider& provider)
{
    core.LimitRequest(ACTION_TYPE_POWER, std::vector<int32_t> {FUZZ_RES_ID_CPU_MAX},
        std::vector<int64_t> {FUZZ_FREQ_CPU_MID, FUZZ_FREQ_CPU_HIGH}, "mismatch");
    core.LimitRequest(ACTION_TYPE_PERF, std::vector<int32_t> {FUZZ_RES_ID_CPU_MAX},
        std::vector<int64_t> {FUZZ_FREQ_CPU_MID}, "invalid_client_low");
    core.LimitRequest(ACTION_TYPE_MAX, std::vector<int32_t> {FUZZ_RES_ID_CPU_MAX},
        std::vector<int64_t> {FUZZ_FREQ_CPU_MID}, "invalid_client_high");
    core.LimitRequest(ACTION_TYPE_POWER,
        std::vector<int32_t> {FUZZ_RES_ID_CPU_MAX, RES_ID_ADDITION + FUZZ_RES_ID_CPU_MAX,
            FUZZ_RES_ID_CPU_MIN},
        std::vector<int64_t> {FUZZ_FREQ_CPU_MID, 1, RESET_VALUE}, "power_limit");
    core.LimitRequest(ACTION_TYPE_THERMAL, std::vector<int32_t> {FUZZ_RES_ID_GPU_FREQ},
        std::vector<int64_t> {provider.ConsumeInt32InRange(FUZZ_FREQ_CPU_HIGH,
            FUZZ_FREQ_GPU_HIGH)}, "thermal_limit");
    core.LimitRequest(ACTION_TYPE_BATTERY,
        std::vector<int32_t> {FUZZ_RES_ID_CPU_MAX, FUZZ_RES_ID_CPU_MIN},
        std::vector<int64_t> {FUZZ_BATTERY_LIMIT_VALUE, INVALID_VALUE}, "battery_limit");
}

void RunDirectCoverage(FuzzDataProvider& provider)
{
    SeedLimitConfig();
    SocPerfThreadWrap wrap;
    PrepareWrap(wrap);
    SeedAlivePerfRequests(wrap);

    SocPerf core;
    PrimeDirectedCore(core, wrap, provider);
    RunLimitEventCases(core, provider);
    RunLimitRequestCases(core, provider);
    DrainQueue(wrap);

    core.SetRequestStatus(false, "disable_request");
    DrainQueue(wrap);
    SeedAlivePerfRequests(wrap);
    core.SetRequestStatus(true, "enable_request");
    core.ClearAllAliveRequest();
    DrainQueue(wrap);
}
} // namespace

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::lock_guard<std::mutex> lock(g_coreLimitMutex);
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
