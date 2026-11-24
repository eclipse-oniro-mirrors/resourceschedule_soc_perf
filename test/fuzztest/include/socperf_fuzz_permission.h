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

#ifndef TEST_FUZZTEST_SOCPERF_FUZZ_PERMISSION_H
#define TEST_FUZZTEST_SOCPERF_FUZZ_PERMISSION_H

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace SOCPERF {
inline NativeTokenInfoParams& GetFuzzTokenInfoParams()
{
    static const char* perms[] = { "ohos.permission.REPORT_RESOURCE_SCHEDULE_EVENT" };
    static NativeTokenInfoParams infoInstance = {
        0, sizeof(perms) / sizeof(perms[0]), 0, nullptr, perms, nullptr, "socperf_test", "system_core",
    };
    return infoInstance;
}

inline void MockProcess()
{
    uint64_t tokenId = GetAccessTokenId(&GetFuzzTokenInfoParams());
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}
} // namespace SOCPERF
} // namespace OHOS

#endif // TEST_FUZZTEST_SOCPERF_FUZZ_PERMISSION_H
