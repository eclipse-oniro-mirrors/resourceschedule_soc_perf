/*
 *  Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SOC_PERF_INTERFACES_INNER_API_SOCPERF_CLIENT_INCLUDE_SOCPERF_IPC_INTERFACE_CODE_H
#define SOC_PERF_INTERFACES_INNER_API_SOCPERF_CLIENT_INCLUDE_SOCPERF_IPC_INTERFACE_CODE_H

/* SAID:1906 */
namespace OHOS {
namespace SOCPERF {
    enum class SocPerfInterfaceCode {
        TRANS_IPC_ID_PERF_REQUEST             = 0x0001,
        TRANS_IPC_ID_PERF_REQUEST_EX          = 0x0002,
        TRANS_IPC_ID_SET_STATUS               = 0x0003,
        TRANS_IPC_ID_SET_THERMAL_LEVEL        = 0x0004,
        TRANS_IPC_ID_POWER_LIMIT_BOOST_FREQ   = 0x0005,
        TRANS_IPC_ID_SET_DEVICE_MODE          = 0x0006,
        TRANS_IPC_ID_REQUEST_CMDID_COUNT      = 0x0007,
        TRANS_IPC_ID_THERMAL_LIMIT_BOOST_FREQ = 0x0008,
        TRANS_IPC_ID_LIMIT_REQUEST            = 0x0009,
    };
} // namespace SOCPERF
} // namespace OHOS

#endif // SOC_PERF_INTERFACES_INNER_API_SOCPERF_CLIENT_INCLUDE_SOCPERF_IPC_INTERFACE_CODE_H
