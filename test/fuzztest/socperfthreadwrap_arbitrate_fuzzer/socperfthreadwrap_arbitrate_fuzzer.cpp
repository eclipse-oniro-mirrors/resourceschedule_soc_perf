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

#define private public
#define protected public
#include "socperf_thread_wrap.h"
#undef private
#undef protected

namespace OHOS {
namespace SOCPERF {
namespace {
std::mutex g_threadWrapMutex;

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

    auto maxRes = std::make_shared<ResNode>(1000, "cpu_max", MAX_FREQUE_NODE, 1001, REPORT_TO_PERFSO);
    maxRes->def = 300;
    maxRes->available = {100, 200, 300};
    config.resourceNodeInfo_[1000] = maxRes;

    auto minRes = std::make_shared<ResNode>(1001, "cpu_min", 0, 1000, REPORT_TO_PERFSO);
    minRes->def = 100;
    minRes->available = {100, 200, 300};
    config.resourceNodeInfo_[1001] = minRes;

    auto govRes = std::make_shared<GovResNode>(1002, "cpu_gov", REPORT_TO_PERFSO);
    govRes->def = 1;
    govRes->available = {1, 2};
    config.resourceNodeInfo_[1002] = govRes;

    auto singleRes = std::make_shared<ResNode>(1003, "gpu_freq", 0, INVALID_VALUE, REPORT_TO_PERFSO);
    singleRes->def = 500;
    singleRes->available = {300, 400, 500};
    config.resourceNodeInfo_[1003] = singleRes;
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

std::shared_ptr<ResAction> MakeAction(int64_t value, int32_t duration, int32_t type, int32_t onOff,
    int32_t cmdId, int64_t endTime)
{
    return std::make_shared<ResAction>(value, duration, type, onOff, cmdId, endTime);
}

void RunAsyncCoverageOnce()
{
    static std::once_flag once;
    std::call_once(once, []() {
        SeedConfig();
        static auto* wrap = new SocPerfThreadWrap();
        PrepareWrap(*wrap);

        auto head = std::make_shared<ResActionItem>(1000);
        head->resAction = MakeAction(300, 1, ACTION_TYPE_PERF, EVENT_ON, 20000, 1000);
        head->next = std::make_shared<ResActionItem>(1001);
        head->next->resAction = MakeAction(100, 1, ACTION_TYPE_PERF, EVENT_ON, 20000, 1000);

        wrap->DoFreqActionPack(head);
        wrap->PostDelayTask(head);
    });
}

void RunDirectArbitrationCases(FuzzDataProvider& provider)
{
    SeedConfig();
    SocPerfThreadWrap wrap;
    PrepareWrap(wrap);

    int64_t levelValue = 0;
    (void)wrap.GetResValueByLevel(9999, 0, levelValue);
    (void)wrap.GetResValueByLevel(1000, -1, levelValue);
    (void)wrap.GetResValueByLevel(1000, provider.ConsumeInt32InRange(0, 5), levelValue);

    auto perfHigh = MakeAction(300, 1, ACTION_TYPE_PERF, EVENT_ON, 20000, 1000);
    auto perfMid = MakeAction(200, 1, ACTION_TYPE_PERF, EVENT_ON, 20001, 900);
    auto perfSame = MakeAction(300, 1, ACTION_TYPE_PERF, EVENT_ON, 20000, 1100);
    auto perfOff = MakeAction(300, 1, ACTION_TYPE_PERF, EVENT_OFF, 20000, 1000);
    auto invalidPerf = MakeAction(100, 1, ACTION_TYPE_PERF, 99, 20002, 700);
    auto powerOn = MakeAction(150, 1, ACTION_TYPE_POWER, EVENT_ON, -1, 800);
    auto thermalOn = MakeAction(180, 1, ACTION_TYPE_THERMAL, EVENT_ON, -1, 700);
    auto levelAction = MakeAction(provider.ConsumeInt32InRange(0, 2), 1, ACTION_TYPE_PERFLVL, EVENT_ON, 21000, 900);

    wrap.DoFreqAction(9999, perfHigh);
    wrap.DoFreqAction(1000, perfHigh);
    wrap.DoFreqActionLevel(RES_ID_ADDITION + 1000, levelAction);

    auto status = wrap.resStatusInfo_[1000];
    wrap.HandleResAction(1000, ACTION_TYPE_PERF, perfHigh, status);
    wrap.HandleResAction(1000, ACTION_TYPE_PERF, perfSame, status);
    wrap.UpdateResActionListByInstantMsg(1000, ACTION_TYPE_PERF, perfOff, status);
    wrap.UpdateResActionListByInstantMsg(1000, ACTION_TYPE_PERF, invalidPerf, status);

    status->resActionList[ACTION_TYPE_POWER].push_back(powerOn);
    wrap.UpdateResActionListByDelayedMsg(1000, ACTION_TYPE_POWER, powerOn, status);

    status->resActionList[ACTION_TYPE_THERMAL].push_back(thermalOn);
    wrap.UpdateResActionList(1000, thermalOn, true);
    wrap.UpdateResActionList(1001, MakeAction(160, 1, ACTION_TYPE_THERMAL, EVENT_ON, -1, 650), false);

    status->resActionList[ACTION_TYPE_PERF].clear();
    status->resActionList[ACTION_TYPE_PERF].push_back(perfHigh);
    status->resActionList[ACTION_TYPE_PERF].push_back(perfMid);
    wrap.InnerArbitrateCandidatesValue(ACTION_TYPE_PERF, status);
    wrap.UpdateCandidatesValue(1000, ACTION_TYPE_PERF);

    status->resActionList[ACTION_TYPE_POWER].clear();
    status->resActionList[ACTION_TYPE_POWER].push_back(powerOn);
    status->resActionList[ACTION_TYPE_POWER].push_back(MakeAction(150, 1, ACTION_TYPE_POWER, EVENT_ON, -1, 1200));
    wrap.InnerArbitrateCandidatesValue(ACTION_TYPE_POWER, status);
    wrap.UpdateCandidatesValue(1000, ACTION_TYPE_POWER);

    auto singleStatus = wrap.resStatusInfo_[1003];
    singleStatus->resActionList[ACTION_TYPE_THERMAL].clear();
    wrap.UpdateCandidatesValue(1003, ACTION_TYPE_THERMAL);

    status->candidatesValue[ACTION_TYPE_PERF] = 300;
    status->candidatesValue[ACTION_TYPE_POWER] = 150;
    status->candidatesValue[ACTION_TYPE_THERMAL] = 180;
    wrap.powerLimitBoost_ = false;
    wrap.thermalLimitBoost_ = false;
    wrap.ProcessLimitCase(1000);
    wrap.powerLimitBoost_ = false;
    wrap.thermalLimitBoost_ = true;
    wrap.ProcessLimitCase(1000);
    wrap.powerLimitBoost_ = true;
    wrap.thermalLimitBoost_ = false;
    wrap.ProcessLimitCase(1000);
    wrap.powerLimitBoost_ = true;
    wrap.thermalLimitBoost_ = true;
    wrap.ProcessLimitCase(1000);

    status->candidatesValue[ACTION_TYPE_PERFLVL] = 200;
    wrap.thermalLvl_ = provider.ConsumeBool() ? 1 : 0;
    (void)wrap.ArbitratePairResInPerfLvl(1000);
    status->candidatesValue[ACTION_TYPE_PERFLVL] = INVALID_VALUE;
    (void)wrap.ArbitratePairResInPerfLvl(1003);

    wrap.ArbitrateCandidate(1000);
    wrap.ArbitratePairRes(1002, false);
    wrap.ArbitratePairRes(1003, true);
    wrap.ArbitratePairRes(1000, provider.ConsumeBool());
    wrap.ArbitratePairRes(1001, provider.ConsumeBool());

    wrap.UpdatePairResValue(1000, 300, 1001, 100);
    wrap.UpdateCurrentValue(1000, 280);

    singleStatus->candidatesValue[ACTION_TYPE_PERF] = INVALID_VALUE;
    singleStatus->candidatesValue[ACTION_TYPE_POWER] = INVALID_VALUE;
    singleStatus->candidatesValue[ACTION_TYPE_THERMAL] = INVALID_VALUE;
    singleStatus->candidatesValue[ACTION_TYPE_PERFLVL] = INVALID_VALUE;
    (void)wrap.ExistNoCandidate(1003, singleStatus);

    status->candidatesValue[ACTION_TYPE_PERF] = 300;
    (void)wrap.ExistNoCandidate(1000, status);
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
