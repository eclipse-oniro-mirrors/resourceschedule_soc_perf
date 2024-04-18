/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef SOC_PERF_INTERFACES_INNER_API_SOCPERF_CLIENT_INCLUDE_I_SOCPERF_SERVICE_H
#define SOC_PERF_INTERFACES_INNER_API_SOCPERF_CLIENT_INCLUDE_I_SOCPERF_SERVICE_H

#include "iremote_stub.h"
#include "socperf_action_type.h"

namespace OHOS {
namespace SOCPERF {
class ISocPerfService : public IRemoteBroker {
public:
    /**
     * @brief Sending a performance request.
     *
     * @param cmdId scene id defined in config file.
     * @param msg Additional string info, which is used for other extensions.
     */
    virtual void PerfRequest(int32_t cmdId, const std::string& msg) = 0;

    /**
     * @brief Sending a performance request.
     *
     * @param cmdId Scene id defined in config file.
     * @param onOffTag Indicates the start of end of a long-term frequency increase event.
     * @param msg Additional string info, which is used for other extensions.
     */
    virtual void PerfRequestEx(int32_t cmdId, bool onOffTag, const std::string& msg) = 0;

    /**
     * @brief Sending a power limit boost request.
     *
     * @param onOffTag Indicates the start of end of a power limit boost event.
     * @param msg Additional string info, which is used for other extensions.
     */
    virtual void PowerLimitBoost(bool onOffTag, const std::string& msg) = 0;

    /**
     * @brief Sending a thermal limit boost request.
     *
     * @param onOffTag Indicates the start of end of a thermal limit boost event.
     * @param msg Additional string info, which is used for other extensions.
     */
    virtual void ThermalLimitBoost(bool onOffTag, const std::string& msg) = 0;

    /**
     * @brief Sending a limit request.
     *
     * @param clientId Used to indentify the caller of frequency limiting, such as
     * the thermal module or power consumption module.
     * @param configs Indicates the specific value to be limited.
     * @param msg Additional string info, which is used for other extensions.
     */
    virtual void LimitRequest(int32_t clientId,
        const std::vector<int32_t>& tags, const std::vector<int64_t>& configs, const std::string& msg) = 0;

    /**
     * @brief set socperf server status, enable or disable
     *
     * @param status true means enable socperfserver, false means disable socperfserver
     * @param msg the reason why we need change socperfserver status
     */
    virtual void SetRequestStatus(bool status, const std::string& msg) = 0;

    /**
     * @brief set thermal level intermal for perfquest
     *
     * @param level thermal level
     */
    virtual void SetThermalLevel(int32_t level) = 0;

    /**
     * @brief send the device mode, enable or disable
     *
     * @param mode the mode which will to be changed
     * @param status true means socperfserver enter the device mode, false quit the device mode
     */
    virtual void RequestDeviceMode(const std::string& mode, bool status) = 0;

    /**
     * @brief get cmd Id count, cmdID is trigger, its count++
     * @param msg the reason
     * @return cmdId count, as 10000:xx,10001:xx
     */
    virtual std::string RequestCmdIdCount(const std::string& msg) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"Resourceschedule.ISocPerfService");
};
} // namespace SOCPERF
} // namespace OHOS

#endif // SOC_PERF_INTERFACES_INNER_API_SOCPERF_CLIENT_INCLUDE_I_SOCPERF_SERVICE_H
