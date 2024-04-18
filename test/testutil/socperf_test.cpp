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


#include <cstdint>           // for int32_t
#include <cstdlib>           // for atoi
#include <vector>            // for vector
#include <cstring>           // for strcmp
#include "socperf_client.h"  // for SocPerfClient
#include "socperf_log.h"

const static int32_t PARAMETERS_NUM_MIN        = 2;
const static int32_t PARAMETERS_NUM_WITHOUT_EX = 3;
const static int32_t PARAMETERS_NUM_WITH_EX    = 4;
const static int32_t PARAMETERS_NUM_LIMIT      = 5;

static void PerfRequest(int32_t argc, char *argv[])
{
    if (argc == PARAMETERS_NUM_WITHOUT_EX) {
        char* cmdId = argv[2];
        if (cmdId) {
            OHOS::SOCPERF::SocPerfClient::GetInstance().PerfRequest(atoi(cmdId), "");
        }
    }
}

static void PerfRequestEx(int32_t argc, char *argv[])
{
    if (argc == PARAMETERS_NUM_WITH_EX) {
        char* cmdId = argv[2];
        char* onOffTag = argv[3];
        if (cmdId && onOffTag) {
            if (strcmp(onOffTag, "true") == 0) {
                OHOS::SOCPERF::SocPerfClient::GetInstance().PerfRequestEx(atoi(cmdId), true, "");
            } else if (strcmp(onOffTag, "false") == 0) {
                OHOS::SOCPERF::SocPerfClient::GetInstance().PerfRequestEx(atoi(cmdId), false, "");
            }
        }
    }
}

static void PowerLimitBoost(int32_t argc, char *argv[])
{
    if (argc == PARAMETERS_NUM_WITHOUT_EX) {
        char* onOffTag = argv[2];
        if (onOffTag) {
            if (strcmp(onOffTag, "true") == 0) {
                OHOS::SOCPERF::SocPerfClient::GetInstance().PowerLimitBoost(true, "");
            } else if (strcmp(onOffTag, "false") == 0) {
                OHOS::SOCPERF::SocPerfClient::GetInstance().PowerLimitBoost(false, "");
            }
        }
    }
}

static void ThermalLimitBoost(int32_t argc, char *argv[])
{
    if (argc == PARAMETERS_NUM_WITHOUT_EX) {
        char* onOffTag = argv[2];
        if (onOffTag) {
            if (strcmp(onOffTag, "true") == 0) {
                OHOS::SOCPERF::SocPerfClient::GetInstance().ThermalLimitBoost(true, "");
            } else if (strcmp(onOffTag, "false") == 0) {
                OHOS::SOCPERF::SocPerfClient::GetInstance().ThermalLimitBoost(false, "");
            }
        }
    }
}

static void LimitRequest(int32_t argc, char *argv[])
{
    if (argc == PARAMETERS_NUM_LIMIT) {
        char* clientId = argv[2];
        char* tags = argv[3];
        char* configs = argv[4];
        std::vector<int32_t> tagsVector = { atoi(tags) };
        std::vector<int64_t> configsVector = { atoll(configs) };
        OHOS::SOCPERF::SocPerfClient::GetInstance().LimitRequest(atoi(clientId), tagsVector, configsVector, "");
    }
}

static void SetRequestStatus(int32_t argc, char *argv[])
{
    if (argc == PARAMETERS_NUM_WITHOUT_EX) {
        char* status = argv[2];
        if (strcmp(status, "true") == 0) {
            OHOS::SOCPERF::SocPerfClient::GetInstance().SetRequestStatus(true, "");
        } else if (strcmp(status, "false") == 0) {
            OHOS::SOCPERF::SocPerfClient::GetInstance().SetRequestStatus(false, "");
        }
    }
}

static void SetThermalLevel(int32_t argc, char *argv[])
{
    if (argc == PARAMETERS_NUM_WITHOUT_EX) {
        char* level = argv[2];
        OHOS::SOCPERF::SocPerfClient::GetInstance().SetThermalLevel(atoi(level));
    }
}

static void RequestDeviceMode(int32_t argc, char *argv[])
{
    if (argc == PARAMETERS_NUM_WITHOUT_EX) {
        std::string mode = argv[2];
        char* status = argv[3];
        if (strcmp(status, "true") == 0) {
            OHOS::SOCPERF::SocPerfClient::GetInstance().RequestDeviceMode(mode, true);
        } else if (strcmp(status, "false") == 0) {
            OHOS::SOCPERF::SocPerfClient::GetInstance().RequestDeviceMode(mode, false);
        }
    }
}

static void RequestCmdIdCount(int32_t argc, char *argv[])
{
    if (argc == PARAMETERS_NUM_MIN) {
        std::string ret = OHOS::SOCPERF::SocPerfClient::GetInstance().RequestCmdIdCount("");
        SOC_PERF_LOGI("%{public}s", ret.c_str());
    }
}

int32_t main(int32_t argc, char *argv[])
{
    if (argc >= PARAMETERS_NUM_MIN && argv) {
        char* function = argv[1];
        if (strcmp(function, "PerfRequest") == 0) {
            PerfRequest(argc, argv);
        } else if (strcmp(function, "PerfRequestEx") == 0) {
            PerfRequestEx(argc, argv);
        } else if (strcmp(function, "PowerLimitBoost") == 0) {
            PowerLimitBoost(argc, argv);
        } else if (strcmp(function, "ThermalLimitBoost") == 0) {
            ThermalLimitBoost(argc, argv);
        } else if (strcmp(function, "LimitRequest") == 0) {
            LimitRequest(argc, argv);
        } else if (strcmp(function, "SetRequestStatus") == 0) {
            SetRequestStatus(argc, argv);
        } else if (strcmp(function, "SetThermalLevel") == 0) {
            SetThermalLevel(argc, argv);
        } else if (strcmp(function, "RequestDeviceMode") == 0) {
            RequestDeviceMode(argc, argv);
        } else if (strcmp(function, "RequestCmdIdCount") == 0) {
            RequestCmdIdCount(argc, argv);
        }
    }
    return 0;
}
