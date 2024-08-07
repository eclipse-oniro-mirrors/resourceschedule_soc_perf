/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "socperf_stub.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "parameters.h"
#include "socperf_ipc_interface_code.h"
#include "socperf_log.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace SOCPERF {
namespace {
    constexpr int32_t HIVIEW_UID = 1201;
    constexpr int32_t MSG_STRING_MAX_LEN = 1024;
    constexpr int32_t MSG_VECTOR_MAX_LEN = 1024;
    constexpr int32_t MSG_VECTOR_INVALID_LEN = 0;
    const int32_t ENG_MODE = OHOS::system::GetIntParameter("const.debuggable", 0);
}
int32_t SocPerfStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (GetDescriptor() != remoteDescriptor || !HasPerfPermission()) {
        return ERR_INVALID_STATE;
    }

    int32_t ret = ERR_OK;
    switch (code) {
        case static_cast<uint32_t>(SocPerfInterfaceCode::TRANS_IPC_ID_PERF_REQUEST): {
            ret = StubPerfRequest(data);
            break;
        }
        case static_cast<uint32_t>(SocPerfInterfaceCode::TRANS_IPC_ID_PERF_REQUEST_EX): {
            ret = StubPerfRequestEx(data);
            break;
        }
        case static_cast<uint32_t>(SocPerfInterfaceCode::TRANS_IPC_ID_POWER_LIMIT_BOOST_FREQ): {
            ret = StubPowerLimitBoost(data);
            break;
        }
        case static_cast<uint32_t>(SocPerfInterfaceCode::TRANS_IPC_ID_THERMAL_LIMIT_BOOST_FREQ): {
            ret = StubThermalLimitBoost(data);
            break;
        }
        case static_cast<uint32_t>(SocPerfInterfaceCode::TRANS_IPC_ID_LIMIT_REQUEST): {
            ret = StubLimitRequest(data);
            break;
        }
        default:
            return OnRemoteRequestExt(code, data, reply, option);
    }
    return ret;
}

int32_t SocPerfStub::OnRemoteRequestExt(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    int32_t ret = ERR_OK;
    switch (code) {
        case static_cast<uint32_t>(SocPerfInterfaceCode::TRANS_IPC_ID_SET_STATUS): {
            ret = StubSetRequestStatus(data);
            break;
        }
        case static_cast<uint32_t>(SocPerfInterfaceCode::TRANS_IPC_ID_SET_THERMAL_LEVEL): {
            ret = StubSetThermalLevel(data);
            break;
        }
        case static_cast<uint32_t>(SocPerfInterfaceCode::TRANS_IPC_ID_SET_DEVICE_MODE): {
            ret = StubRequestDeviceMode(data);
            break;
        }
        case static_cast<uint32_t>(SocPerfInterfaceCode::TRANS_IPC_ID_REQUEST_CMDID_COUNT): {
            ret = StubRequestCmdIdCount(data, reply);
            break;
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return ret;
}

int32_t SocPerfStub::StubPerfRequest(MessageParcel &data)
{
    int32_t cmdId = 0;
    if (!data.ReadInt32(cmdId)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read cmdId failed", __func__);
        return ERR_INVALID_STATE;
    }

    std::string msg;
    if (!data.ReadString(msg)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read msg failed", __func__);
        return ERR_INVALID_STATE;
    }
    if (msg.length() > MSG_STRING_MAX_LEN) {
        return ERR_INVALID_STATE;
    }

    PerfRequest(cmdId, msg);
    return ERR_OK;
}

int32_t SocPerfStub::StubPerfRequestEx(MessageParcel &data)
{
    int32_t cmdId = 0;
    if (!data.ReadInt32(cmdId)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read cmdId failed", __func__);
        return ERR_INVALID_STATE;
    }

    bool onOffTag = false;
    if (!data.ReadBool(onOffTag)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read onOffTag failed", __func__);
        return ERR_INVALID_STATE;
    }

    std::string msg;
    if (!data.ReadString(msg)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read msg failed", __func__);
        return ERR_INVALID_STATE;
    }
    if (msg.length() > MSG_STRING_MAX_LEN) {
        return ERR_INVALID_STATE;
    }

    PerfRequestEx(cmdId, onOffTag, msg);
    return ERR_OK;
}

int32_t SocPerfStub::StubPowerLimitBoost(MessageParcel &data)
{
    bool onOffTag = false;
    if (!data.ReadBool(onOffTag)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read onOffTag failed", __func__);
        return ERR_INVALID_STATE;
    }

    std::string msg;
    if (!data.ReadString(msg)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read msg failed", __func__);
        return ERR_INVALID_STATE;
    }
    if (msg.length() > MSG_STRING_MAX_LEN) {
        return ERR_INVALID_STATE;
    }

    PowerLimitBoost(onOffTag, msg);
    return ERR_OK;
}

int32_t SocPerfStub::StubThermalLimitBoost(MessageParcel &data)
{
    bool onOffTag = false;
    if (!data.ReadBool(onOffTag)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read onOffTag failed", __func__);
        return ERR_INVALID_STATE;
    }

    std::string msg;
    if (!data.ReadString(msg)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read msg failed", __func__);
        return ERR_INVALID_STATE;
    }
    if (msg.length() > MSG_STRING_MAX_LEN) {
        return ERR_INVALID_STATE;
    }

    ThermalLimitBoost(onOffTag, msg);
    return ERR_OK;
}

int32_t SocPerfStub::StubLimitRequest(MessageParcel &data)
{
    int32_t clientId;
    if (!data.ReadInt32(clientId)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read clientId failed", __func__);
        return ERR_INVALID_STATE;
    }

    std::vector<int32_t> tags;
    if (!data.ReadInt32Vector(&tags)) {
        SOC_PERF_LOGE("error tags to do StubLimitRequest");
        return ERR_INVALID_STATE;
    }
    if (tags.size() == MSG_VECTOR_INVALID_LEN || tags.size() > MSG_VECTOR_MAX_LEN) {
        SOC_PERF_LOGE("error tags to do StubLimitRequest");
        return ERR_INVALID_STATE;
    }

    std::vector<int64_t> configs;
    if (!data.ReadInt64Vector(&configs)) {
        SOC_PERF_LOGE("error configs to do StubLimitRequest");
        return ERR_INVALID_STATE;
    }
    if (configs.size() == MSG_VECTOR_INVALID_LEN || configs.size() > MSG_VECTOR_MAX_LEN) {
        SOC_PERF_LOGE("error configs to do StubLimitRequest");
        return ERR_INVALID_STATE;
    }

    std::string msg;
    if (!data.ReadString(msg)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read msg failed", __func__);
        return ERR_INVALID_STATE;
    }
    if (msg.length() > MSG_STRING_MAX_LEN) {
        return ERR_INVALID_STATE;
    }

    LimitRequest(clientId, tags, configs, msg);
    return ERR_OK;
}

int32_t SocPerfStub::StubSetRequestStatus(MessageParcel &data)
{
    bool requestEnable;
    if (!data.ReadBool(requestEnable)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read requestEnable failed", __func__);
        return ERR_INVALID_STATE;
    }

    std::string msg;
    if (!data.ReadString(msg)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read msg failed", __func__);
        return ERR_INVALID_STATE;
    }
    if (msg.length() > MSG_STRING_MAX_LEN) {
        return ERR_INVALID_STATE;
    }

    SetRequestStatus(requestEnable, msg);
    return ERR_OK;
}

int32_t SocPerfStub::StubSetThermalLevel(MessageParcel &data)
{
    int32_t levelId;
    if (!data.ReadInt32(levelId)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read levelId failed", __func__);
        return ERR_INVALID_STATE;
    }

    SetThermalLevel(levelId);
    return ERR_OK;
}

int32_t SocPerfStub::StubRequestDeviceMode(MessageParcel &data)
{
    std::string mode;
    if (!data.ReadString(mode)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read mode failed", __func__);
        return ERR_INVALID_STATE;
    }
    if (mode.length() > MSG_STRING_MAX_LEN) {
        return ERR_INVALID_STATE;
    }

    bool status;
    if (!data.ReadBool(status)) {
        SOC_PERF_LOGE("SocPerfStub::%{public}s read status failed", __func__);
        return ERR_INVALID_STATE;
    }

    RequestDeviceMode(mode, status);
    return ERR_OK;
}

int32_t SocPerfStub::StubRequestCmdIdCount(MessageParcel &data, MessageParcel &reply)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::string msg;
    if ((ENG_MODE == 0 && callingUid != HIVIEW_UID) || !data.ReadString(msg)) {
        SOC_PERF_LOGE("not have right to do RequestCmdIdCount");
        return ERR_INVALID_STATE;
    }
    if (!reply.WriteString(RequestCmdIdCount(msg))) {
        SOC_PERF_LOGE("write RequestCmdIdCount ret failed");
        return ERR_INVALID_STATE;
    }
    return ERR_OK;
}

const std::string NEEDED_PERMISSION = "ohos.permission.REPORT_RESOURCE_SCHEDULE_EVENT";

bool SocPerfStub::HasPerfPermission()
{
    uint32_t accessToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(accessToken);
    if (int(tokenType) == OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
        if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
            SOC_PERF_LOGE("Invalid Permission to SocPerf");
            return false;
        }
    }
    int32_t hasPermission = Security::AccessToken::AccessTokenKit::VerifyAccessToken(accessToken, NEEDED_PERMISSION);
    if (hasPermission != 0) {
        SOC_PERF_LOGE("SocPerf: not have Permission");
        return false;
    }
    return true;
}
} // namespace SOCPERF
} // namespace OHOS
