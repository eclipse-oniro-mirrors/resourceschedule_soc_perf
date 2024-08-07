/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef SOC_PERF_SERVICES_SERVER_INCLUDE_SOCPERF_STUB_H
#define SOC_PERF_SERVICES_SERVER_INCLUDE_SOCPERF_STUB_H

#include <cstdint>              // for int32_t, uint32_t
#include "i_socperf_service.h"

namespace OHOS {
namespace SOCPERF {
class SocPerfStub : public IRemoteStub<ISocPerfService> {
public:
    SocPerfStub() = default;
    ~SocPerfStub() override = default;
    DISALLOW_COPY_AND_MOVE(SocPerfStub);

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
private:
    bool HasPerfPermission();
    int32_t OnRemoteRequestExt(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int32_t StubPerfRequest(MessageParcel &data);
    int32_t StubPerfRequestEx(MessageParcel &data);
    int32_t StubPowerLimitBoost(MessageParcel &data);
    int32_t StubThermalLimitBoost(MessageParcel &data);
    int32_t StubLimitRequest(MessageParcel &data);
    int32_t StubSetRequestStatus(MessageParcel &data);
    int32_t StubSetThermalLevel(MessageParcel &data);
    int32_t StubRequestDeviceMode(MessageParcel &data);
    int32_t StubRequestCmdIdCount(MessageParcel &data, MessageParcel &reply);
};
} // namespace SOCPERF
} // namespace OHOS

#endif // SOC_PERF_SERVICES_SERVER_INCLUDE_SOCPERF_STUB_H
