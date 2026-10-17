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

#include "socperfthreadwrap_arbitrate_fuzzer.h"

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
std::mutex g_threadWrapMutex;

constexpr int64_t FUZZ_POWER_CANDIDATE_VALUE = 150;
constexpr int64_t FUZZ_THERMAL_CANDIDATE_VALUE = 180;
constexpr int64_t FUZZ_ACTION_END_TIME = 1000;
constexpr int32_t FUZZ_INVALID_ON_OFF = 99;
constexpr int32_t FUZZ_LEVEL_LOOKUP_MAX = 5;
constexpr int32_t FUZZ_PERF_LEVEL_MAX = 2;
constexpr int32_t FUZZ_FREQ_CPU_MID_HIGH = 280;

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

void SeedConfig()
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

    auto govRes = std::make_shared<GovResNode>(FUZZ_RES_ID_CPU_GOV, "cpu_gov", REPORT_TO_PERFSO);
    govRes->def = 1;
    govRes->available = {1, FUZZ_GOV_PERFORMANCE};
    config.resourceNodeInfo_[FUZZ_RES_ID_CPU_GOV] = govRes;

    auto singleRes = std::make_shared<ResNode>(FUZZ_RES_ID_GPU_FREQ, "gpu_freq", 0,
        INVALID_VALUE, REPORT_TO_PERFSO);
    singleRes->def = FUZZ_FREQ_GPU_HIGH;
    singleRes->available = {FUZZ_FREQ_CPU_HIGH, FUZZ_FREQ_GPU_MID, FUZZ_FREQ_GPU_HIGH};
    config.resourceNodeInfo_[FUZZ_RES_ID_GPU_FREQ] = singleRes;
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

std::shared_ptr<ResAction> MakeAction(const ResActionSeed& seed)
{
    return std::make_shared<ResAction>(seed.value, seed.duration, seed.type, seed.onOff,
        seed.cmdId, seed.endTime);
}

void RunAsyncCoverageOnce()
{
    static std::once_flag once;
    std::call_once(once, []() {
        SeedConfig();
        static auto* wrap = new SocPerfThreadWrap();
        PrepareWrap(*wrap);

        auto head = std::make_shared<ResActionItem>(FUZZ_RES_ID_CPU_MAX);
        head->resAction = MakeAction({FUZZ_FREQ_CPU_HIGH, 1, ACTION_TYPE_PERF, EVENT_ON,
            FUZZ_CMD_ID_PERF, FUZZ_ACTION_END_TIME});
        head->next = std::make_shared<ResActionItem>(FUZZ_RES_ID_CPU_MIN);
        head->next->resAction = MakeAction({FUZZ_FREQ_CPU_LOW, 1, ACTION_TYPE_PERF, EVENT_ON,
            FUZZ_CMD_ID_PERF, FUZZ_ACTION_END_TIME});

        wrap->DoFreqActionPack(head);
        wrap->PostDelayTask(head);
    });
}

void ExerciseResValueLookup(SocPerfThreadWrap& wrap, FuzzDataProvider& provider)
{
    int64_t levelValue = 0;
    (void)wrap.GetResValueByLevel(FUZZ_RES_ID_UNKNOWN, 0, levelValue);
    (void)wrap.GetResValueByLevel(FUZZ_RES_ID_CPU_MAX, -1, levelValue);
    (void)wrap.GetResValueByLevel(FUZZ_RES_ID_CPU_MAX,
        provider.ConsumeInt32InRange(0, FUZZ_LEVEL_LOOKUP_MAX), levelValue);
}

struct DirectCaseActions {
    std::shared_ptr<ResAction> perfHigh;
    std::shared_ptr<ResAction> perfMid;
    std::shared_ptr<ResAction> perfSame;
    std::shared_ptr<ResAction> perfOff;
    std::shared_ptr<ResAction> invalidPerf;
    std::shared_ptr<ResAction> powerOn;
    std::shared_ptr<ResAction> thermalOn;
    std::shared_ptr<ResAction> levelAction;
};

DirectCaseActions BuildDirectCaseActions(FuzzDataProvider& provider)
{
    DirectCaseActions actions;
    actions.perfHigh = MakeAction({FUZZ_FREQ_CPU_HIGH, 1, ACTION_TYPE_PERF, EVENT_ON,
        FUZZ_CMD_ID_PERF, FUZZ_ACTION_END_TIME});
    actions.perfMid = MakeAction({FUZZ_FREQ_CPU_MID, 1, ACTION_TYPE_PERF, EVENT_ON,
        FUZZ_CMD_ID_LONG_PERF, 900});
    actions.perfSame = MakeAction({FUZZ_FREQ_CPU_HIGH, 1, ACTION_TYPE_PERF, EVENT_ON,
        FUZZ_CMD_ID_PERF, 1100});
    actions.perfOff = MakeAction({FUZZ_FREQ_CPU_HIGH, 1, ACTION_TYPE_PERF, EVENT_OFF,
        FUZZ_CMD_ID_PERF, FUZZ_ACTION_END_TIME});
    actions.invalidPerf = MakeAction({FUZZ_FREQ_CPU_LOW, 1, ACTION_TYPE_PERF, FUZZ_INVALID_ON_OFF,
        FUZZ_CMD_ID_THERMAL_PERF, 700});
    actions.powerOn = MakeAction({FUZZ_POWER_CANDIDATE_VALUE, 1, ACTION_TYPE_POWER, EVENT_ON,
        -1, 800});
    actions.thermalOn = MakeAction({FUZZ_THERMAL_CANDIDATE_VALUE, 1, ACTION_TYPE_THERMAL,
        EVENT_ON, -1, 700});
    actions.levelAction = MakeAction({provider.ConsumeInt32InRange(0, FUZZ_PERF_LEVEL_MAX), 1,
        ACTION_TYPE_PERFLVL, EVENT_ON, FUZZ_CMD_ID_WEAK_PERF, 900});
    return actions;
}

void ExerciseFreqAndActionList(SocPerfThreadWrap& wrap, const DirectCaseActions& actions)
{
    wrap.DoFreqAction(FUZZ_RES_ID_UNKNOWN, actions.perfHigh);
    wrap.DoFreqAction(FUZZ_RES_ID_CPU_MAX, actions.perfHigh);
    wrap.DoFreqActionLevel(RES_ID_ADDITION + FUZZ_RES_ID_CPU_MAX, actions.levelAction);

    auto status = wrap.resStatusInfo_[FUZZ_RES_ID_CPU_MAX];
    wrap.HandleResAction(FUZZ_RES_ID_CPU_MAX, ACTION_TYPE_PERF, actions.perfHigh, status);
    wrap.HandleResAction(FUZZ_RES_ID_CPU_MAX, ACTION_TYPE_PERF, actions.perfSame, status);
    wrap.UpdateResActionListByInstantMsg(FUZZ_RES_ID_CPU_MAX, ACTION_TYPE_PERF,
        actions.perfOff, status);
    wrap.UpdateResActionListByInstantMsg(FUZZ_RES_ID_CPU_MAX, ACTION_TYPE_PERF,
        actions.invalidPerf, status);

    status->resActionList[ACTION_TYPE_POWER].push_back(actions.powerOn);
    wrap.UpdateResActionListByDelayedMsg(FUZZ_RES_ID_CPU_MAX, ACTION_TYPE_POWER,
        actions.powerOn, status);

    status->resActionList[ACTION_TYPE_THERMAL].push_back(actions.thermalOn);
    wrap.UpdateResActionList(FUZZ_RES_ID_CPU_MAX, actions.thermalOn, true);
    wrap.UpdateResActionList(FUZZ_RES_ID_CPU_MIN,
        MakeAction({160, 1, ACTION_TYPE_THERMAL, EVENT_ON, -1, 650}), false);

    status->resActionList[ACTION_TYPE_PERF].clear();
    status->resActionList[ACTION_TYPE_PERF].push_back(actions.perfHigh);
    status->resActionList[ACTION_TYPE_PERF].push_back(actions.perfMid);
    wrap.InnerArbitrateCandidatesValue(ACTION_TYPE_PERF, status);
    wrap.UpdateCandidatesValue(FUZZ_RES_ID_CPU_MAX, ACTION_TYPE_PERF);

    status->resActionList[ACTION_TYPE_POWER].clear();
    status->resActionList[ACTION_TYPE_POWER].push_back(actions.powerOn);
    status->resActionList[ACTION_TYPE_POWER].push_back(
        MakeAction({FUZZ_POWER_CANDIDATE_VALUE, 1, ACTION_TYPE_POWER, EVENT_ON, -1, 1200}));
    wrap.InnerArbitrateCandidatesValue(ACTION_TYPE_POWER, status);
    wrap.UpdateCandidatesValue(FUZZ_RES_ID_CPU_MAX, ACTION_TYPE_POWER);

    auto singleStatus = wrap.resStatusInfo_[FUZZ_RES_ID_GPU_FREQ];
    singleStatus->resActionList[ACTION_TYPE_THERMAL].clear();
    wrap.UpdateCandidatesValue(FUZZ_RES_ID_GPU_FREQ, ACTION_TYPE_THERMAL);
}

void ExerciseLimitCaseMatrix(SocPerfThreadWrap& wrap)
{
    auto status = wrap.resStatusInfo_[FUZZ_RES_ID_CPU_MAX];
    status->candidatesValue[ACTION_TYPE_PERF] = FUZZ_FREQ_CPU_HIGH;
    status->candidatesValue[ACTION_TYPE_POWER] = FUZZ_POWER_CANDIDATE_VALUE;
    status->candidatesValue[ACTION_TYPE_THERMAL] = FUZZ_THERMAL_CANDIDATE_VALUE;

    wrap.powerLimitBoost_ = false;
    wrap.thermalLimitBoost_ = false;
    wrap.ProcessLimitCase(FUZZ_RES_ID_CPU_MAX);
    wrap.powerLimitBoost_ = false;
    wrap.thermalLimitBoost_ = true;
    wrap.ProcessLimitCase(FUZZ_RES_ID_CPU_MAX);
    wrap.powerLimitBoost_ = true;
    wrap.thermalLimitBoost_ = false;
    wrap.ProcessLimitCase(FUZZ_RES_ID_CPU_MAX);
    wrap.powerLimitBoost_ = true;
    wrap.thermalLimitBoost_ = true;
    wrap.ProcessLimitCase(FUZZ_RES_ID_CPU_MAX);
}

void ExercisePairArbitration(SocPerfThreadWrap& wrap, FuzzDataProvider& provider)
{
    auto status = wrap.resStatusInfo_[FUZZ_RES_ID_CPU_MAX];
    auto singleStatus = wrap.resStatusInfo_[FUZZ_RES_ID_GPU_FREQ];

    status->candidatesValue[ACTION_TYPE_PERFLVL] = FUZZ_FREQ_CPU_MID;
    wrap.thermalLvl_ = provider.ConsumeBool() ? 1 : 0;
    (void)wrap.ArbitratePairResInPerfLvl(FUZZ_RES_ID_CPU_MAX);
    status->candidatesValue[ACTION_TYPE_PERFLVL] = INVALID_VALUE;
    (void)wrap.ArbitratePairResInPerfLvl(FUZZ_RES_ID_GPU_FREQ);

    wrap.ArbitrateCandidate(FUZZ_RES_ID_CPU_MAX);
    wrap.ArbitratePairRes(FUZZ_RES_ID_CPU_GOV, false);
    wrap.ArbitratePairRes(FUZZ_RES_ID_GPU_FREQ, true);
    wrap.ArbitratePairRes(FUZZ_RES_ID_CPU_MAX, provider.ConsumeBool());
    wrap.ArbitratePairRes(FUZZ_RES_ID_CPU_MIN, provider.ConsumeBool());

    wrap.UpdatePairResValue(FUZZ_RES_ID_CPU_MAX, FUZZ_FREQ_CPU_HIGH,
        FUZZ_RES_ID_CPU_MIN, FUZZ_FREQ_CPU_LOW);
    wrap.UpdateCurrentValue(FUZZ_RES_ID_CPU_MAX, FUZZ_FREQ_CPU_MID_HIGH);

    singleStatus->candidatesValue[ACTION_TYPE_PERF] = INVALID_VALUE;
    singleStatus->candidatesValue[ACTION_TYPE_POWER] = INVALID_VALUE;
    singleStatus->candidatesValue[ACTION_TYPE_THERMAL] = INVALID_VALUE;
    singleStatus->candidatesValue[ACTION_TYPE_PERFLVL] = INVALID_VALUE;
    (void)wrap.ExistNoCandidate(FUZZ_RES_ID_GPU_FREQ, singleStatus);

    status->candidatesValue[ACTION_TYPE_PERF] = FUZZ_FREQ_CPU_HIGH;
    (void)wrap.ExistNoCandidate(FUZZ_RES_ID_CPU_MAX, status);
}

void RunDirectArbitrationCases(FuzzDataProvider& provider)
{
    SeedConfig();
    SocPerfThreadWrap wrap;
    PrepareWrap(wrap);

    ExerciseResValueLookup(wrap, provider);
    DirectCaseActions actions = BuildDirectCaseActions(provider);
    ExerciseFreqAndActionList(wrap, actions);
    ExerciseLimitCaseMatrix(wrap);
    ExercisePairArbitration(wrap, provider);
}
} // namespace

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::lock_guard<std::mutex> lock(g_threadWrapMutex);
    FuzzDataProvider provider(data, size);
    RunAsyncCoverageOnce();
    RunDirectArbitrationCases(provider);
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
