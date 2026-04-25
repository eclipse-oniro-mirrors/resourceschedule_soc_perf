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
std::mutex g_coreLimitMutex;

constexpr int32_t RES_CPU_MAX = 1000;
constexpr int32_t RES_CPU_MIN = 1001;
constexpr int32_t RES_CPU_GOV = 1002;
constexpr int32_t RES_GPU_FREQ = 1003;

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

void SeedLimitConfig()
{
    ResetConfig();
    auto& config = SocPerfConfig::GetInstance();

    auto cpuMax = std::make_shared<ResNode>(RES_CPU_MAX, "cpu_max", MAX_FREQUE_NODE, RES_CPU_MIN, REPORT_TO_PERFSO);
    cpuMax->def = 300;
    cpuMax->available = {100, 200, 300};
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
    auto cpuMaxStatus = wrap.resStatusInfo_[RES_CPU_MAX];
    auto cpuMinStatus = wrap.resStatusInfo_[RES_CPU_MIN];
    if (cpuMaxStatus == nullptr || cpuMinStatus == nullptr) {
        return;
    }
    cpuMaxStatus->resActionList[ACTION_TYPE_PERF].push_back(
        MakeResAction(300, 1, ACTION_TYPE_PERF, EVENT_ON, 50000, 3000));
    cpuMinStatus->resActionList[ACTION_TYPE_PERF].push_back(
        MakeResAction(100, 1, ACTION_TYPE_PERF, EVENT_ON, 50000, 3000));
    wrap.UpdateCandidatesValue(RES_CPU_MAX, ACTION_TYPE_PERF);
    wrap.UpdateCandidatesValue(RES_CPU_MIN, ACTION_TYPE_PERF);
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
        core->LimitRequest(ACTION_TYPE_POWER, std::vector<int32_t> {RES_CPU_MAX, RES_ID_ADDITION + RES_CPU_MAX},
            std::vector<int64_t> {200, 1}, "async_power");
        core->LimitRequest(ACTION_TYPE_BATTERY, std::vector<int32_t> {RES_CPU_MIN},
            std::vector<int64_t> {100}, "async_battery");
        DrainQueue(*wrap);
    });
}

void RunDirectCoverage(FuzzDataProvider& provider)
{
    SeedLimitConfig();
    SocPerfThreadWrap wrap;
    PrepareWrap(wrap);
    SeedAlivePerfRequests(wrap);

    SocPerf core;
    core.enabled_ = true;
    core.perfRequestEnable_ = true;
    core.thermalLvl_ = provider.ConsumeInt32InRange(0, 2);
    core.socperfThreadWrap_ = MakeNonOwningWrap(&wrap);
    wrap.thermalLvl_ = core.thermalLvl_;

    core.enabled_ = false;
    core.PowerLimitBoost(true, "disabled_power");
    core.ThermalLimitBoost(true, "disabled_thermal");
    core.LimitRequest(ACTION_TYPE_POWER, std::vector<int32_t> {RES_CPU_MAX}, std::vector<int64_t> {200}, "disabled");
    core.ClearAllAliveRequest();
    core.SetThermalLevel(2);

    core.enabled_ = true;
    core.PowerLimitBoost(true, "Low_battery_limit");
    core.PowerLimitBoost(false, "power_limit");
    std::string powerMsg = provider.ConsumeString(24);
    if (powerMsg.empty() || powerMsg == "Low_battery_limit") {
        powerMsg = "power_limit_fuzz";
    }
    core.PowerLimitBoost(provider.ConsumeBool(), powerMsg);
    core.ThermalLimitBoost(true, "thermal_msg");
    core.ThermalLimitBoost(false, "thermal_msg");
    core.SetThermalLevel(provider.ConsumeInt32InRange(0, 4));

    core.SendLimitRequestEventOn(ACTION_TYPE_POWER, RES_CPU_MAX, provider.ConsumeInt32InRange(100, 300),
        INNER_EVENT_ID_DO_FREQ_ACTION);
    core.SendLimitRequestEventOn(ACTION_TYPE_BATTERY, RES_CPU_MIN, 100, INNER_EVENT_ID_DO_FREQ_ACTION);
    core.SendLimitRequestEventOn(ACTION_TYPE_THERMAL, RES_ID_ADDITION + RES_CPU_MAX,
        provider.ConsumeInt32InRange(0, 2), INNER_EVENT_ID_DO_FREQ_ACTION_LEVEL);
    core.SendLimitRequestEventOn(ACTION_TYPE_POWER, RES_CPU_MAX, INVALID_VALUE, INNER_EVENT_ID_DO_FREQ_ACTION);
    core.SendLimitRequestEventOn(ACTION_TYPE_POWER, RES_CPU_MAX, RESET_VALUE, INNER_EVENT_ID_DO_FREQ_ACTION);

    core.limitRequest_[ACTION_TYPE_THERMAL][RES_GPU_FREQ] = INVALID_VALUE;
    core.SendLimitRequestEventOff(ACTION_TYPE_THERMAL, RES_GPU_FREQ, INNER_EVENT_ID_DO_FREQ_ACTION);
    core.SendLimitRequestEventOff(ACTION_TYPE_POWER, RES_CPU_MAX, INNER_EVENT_ID_DO_FREQ_ACTION);
    core.SendLimitRequestEventOff(ACTION_TYPE_BATTERY, RES_CPU_MIN, INNER_EVENT_ID_DO_FREQ_ACTION);
    core.SendLimitRequestEventOff(ACTION_TYPE_THERMAL, RES_ID_ADDITION + RES_CPU_MAX,
        INNER_EVENT_ID_DO_FREQ_ACTION_LEVEL);

    core.SendLimitRequestEvent(ACTION_TYPE_POWER, 9999, 200);
    core.SendLimitRequestEvent(ACTION_TYPE_POWER, RES_CPU_MAX, provider.ConsumeInt32InRange(100, 300));
    core.SendLimitRequestEvent(ACTION_TYPE_THERMAL, RES_ID_ADDITION + RES_CPU_MAX,
        provider.ConsumeInt32InRange(0, 2));
    core.SendLimitRequestEvent(ACTION_TYPE_BATTERY, RES_CPU_MIN,
        provider.ConsumeBool() ? INVALID_VALUE : provider.ConsumeInt32InRange(100, 200));

    core.LimitRequest(ACTION_TYPE_POWER, std::vector<int32_t> {RES_CPU_MAX},
        std::vector<int64_t> {200, 300}, "mismatch");
    core.LimitRequest(ACTION_TYPE_PERF, std::vector<int32_t> {RES_CPU_MAX},
        std::vector<int64_t> {200}, "invalid_client_low");
    core.LimitRequest(ACTION_TYPE_MAX, std::vector<int32_t> {RES_CPU_MAX},
        std::vector<int64_t> {200}, "invalid_client_high");
    core.LimitRequest(ACTION_TYPE_POWER, std::vector<int32_t> {RES_CPU_MAX, RES_ID_ADDITION + RES_CPU_MAX, RES_CPU_MIN},
        std::vector<int64_t> {200, 1, RESET_VALUE}, "power_limit");
    core.LimitRequest(ACTION_TYPE_THERMAL, std::vector<int32_t> {RES_GPU_FREQ},
        std::vector<int64_t> {provider.ConsumeInt32InRange(300, 500)}, "thermal_limit");
    core.LimitRequest(ACTION_TYPE_BATTERY, std::vector<int32_t> {RES_CPU_MAX, RES_CPU_MIN},
        std::vector<int64_t> {220, INVALID_VALUE}, "battery_limit");
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
