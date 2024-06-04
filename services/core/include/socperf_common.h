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

#ifndef SOC_PERF_SERVICES_CORE_INCLUDE_SOCPERF_COMMON_H
#define SOC_PERF_SERVICES_CORE_INCLUDE_SOCPERF_COMMON_H

#include <climits>
#include <list>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include "socperf_log.h"
#include "socperf_action_type.h"

namespace OHOS {
namespace SOCPERF {
enum EventType {
    EVENT_INVALID = -1,
    EVENT_OFF,
    EVENT_ON
};

const std::string SOCPERF_RESOURCE_CONFIG_XML = "etc/soc_perf/socperf_resource_config.xml";
const std::string SOCPERF_BOOST_CONFIG_XML    = "etc/soc_perf/socperf_boost_config.xml";
const std::string SOCPERF_BOOST_CONFIG_XML_EXT    = "etc/soc_perf/socperf_boost_config_ext.xml";
const int64_t MAX_INT_VALUE                       = 0x7FFFFFFFFFFFFFFF;
const int64_t MIN_INT_VALUE                       = 0x8000000000000000;
const int32_t INVALID_VALUE                       = INT_MIN;
const int32_t RESET_VALUE                         = -1;
/*
 * Divide all resource id into five sections, resource of each section is processed in an individual queue.
 * threadWrapId = resourceId / RES_ID_NUMS_PER_TYPE - 1
 * Resource section:    [1000, 1999]   [2000, 2999]   [3000, 3999]   [4000, 4999]   [5000, 5999]
 * queue: socperfThreadWraps[0] socperfThreadWraps[1] socperfThreadWraps[2] socperfThreadWraps[3] socperfThreadWraps[4]
 */
const int32_t MAX_QUEUE_NUM                 = 5;
const int32_t MIN_RESOURCE_ID                     = 1000;
const int32_t MAX_RESOURCE_ID                     = 5999;
const int32_t RES_ID_ADDITION                     = 10000;
const int32_t RES_ID_AND_VALUE_PAIR               = 2;
const int32_t RES_ID_NUMS_PER_TYPE                = 1000;
const int32_t RES_ID_NUMS_PER_TYPE_EXT            = 10000;
const int32_t WRITE_NODE                          = 0;
const int32_t REPORT_TO_PERFSO                    = 1;
const int32_t INVALID_THERMAL_CMD_ID              = -1;
const int32_t MIN_THERMAL_LVL                     = 0;
const int32_t RES_MODE_AND_ID_PAIR                = 2;
const int32_t MAX_RES_MODE_LEN                    = 64;
const int32_t MAX_FREQUE_NODE                     = 1;

const std::unordered_map<std::string, std::vector<std::string>> MUTEX_MODE = {
    {"displaySub", {"displayMain", "displayFull"}},
    {"displayMain", {"displaySub", "displayFull"}},
    {"displayFull", {"displayMain", "displaySub"}}
};

class ResourceNode {
public:
    int32_t id;
    std::string name;
    int64_t def;
    std::unordered_set<int64_t> available;
    int32_t persistMode;
    bool isGov;
    bool isMaxValue;
public:
    ResourceNode(int32_t id, const std::string& name, int32_t persistMode, bool isGov, bool isMaxValue) : id(id),
        name(name), def(INVALID_VALUE), persistMode(persistMode), isGov(isGov), isMaxValue(isMaxValue) {}
    virtual ~ResourceNode() {};
    virtual void PrintString() {};
};

class ResNode : public ResourceNode {
public:
    std::string path;
    int32_t pair;

public:
    ResNode(int32_t resId, const std::string& resName, int32_t resMode, int32_t resPair, int32_t resPersistMode)
        : ResourceNode(resId, resName, resPersistMode, false, resMode == MAX_FREQUE_NODE)
    {
        pair = resPair;
    }
    ~ResNode() {}

    void PrintString()
    {
        SOC_PERF_LOGD("resNode-> id: [%{public}d], name: [%{public}s]", id, name.c_str());
        SOC_PERF_LOGD("          path: [%{public}s]", path.c_str());
        SOC_PERF_LOGD("          def: [%{public}lld], mode: [%{public}d], pair: [%{public}d]",
            (long long)def, isMaxValue, pair);
        std::string str;
        str.append("available(").append(std::to_string((int32_t)available.size())).append("): ");
        str.append("[");
        for (auto validValue : available) {
            str.append(std::to_string(validValue)).append(",");
        }
        if (!available.empty()) {
            str.pop_back();
        }
        str.append("]");
        SOC_PERF_LOGD("          %{public}s", str.c_str());
    }
};

class GovResNode : public ResourceNode {
public:
    std::vector<std::string> paths;
    std::unordered_map<int64_t, std::vector<std::string>> levelToStr;

public:
    GovResNode(int32_t govResId, const std::string& govResName, int32_t govPersistMode)
        : ResourceNode(govResId, govResName, govPersistMode, true, false) {}
    ~GovResNode() {}

    void PrintString()
    {
        SOC_PERF_LOGD("govResNode-> id: [%{public}d], name: [%{public}s]", id, name.c_str());
        SOC_PERF_LOGD("             def: [%{public}lld]", (long long)def);
        for (auto path : paths) {
            SOC_PERF_LOGD("             path: [%{public}s]", path.c_str());
        }
        std::string str;
        str.append("available(").append(std::to_string((int32_t)available.size())).append("): ");
        str.append("[");
        for (auto validValue : available) {
            str.append(std::to_string(validValue)).append(",");
        }
        if (!available.empty()) {
            str.pop_back();
        }
        str.append("]");
        SOC_PERF_LOGD("             %{public}s", str.c_str());
        for (auto iter = levelToStr.begin(); iter != levelToStr.end(); ++iter) {
            std::string str2;
            int64_t level = iter->first;
            std::vector<std::string> result = iter->second;
            for (int32_t i = 0; i < (int32_t)result.size(); i++) {
                str2.append(result[i]).append(",");
            }
            if (!result.empty()) {
                str2.pop_back();
            }
            SOC_PERF_LOGD("             %{public}lld: [%{public}s]", (long long)level, str2.c_str());
        }
    }
};

class Action {
public:
    int32_t thermalCmdId_ = INVALID_THERMAL_CMD_ID;
    int32_t thermalLvl_ = MIN_THERMAL_LVL;
    int32_t duration;
    std::vector<int64_t> variable;

public:
    Action() {}
    ~Action() {}
};

class Actions {
public:
    int32_t id;
    std::string name;
    std::list<std::shared_ptr<Action>> actionList;
    std::unordered_map<std::string, int32_t> modeMap;
    bool isLongTimePerf = false;

public:
    Actions(int32_t cmdId, const std::string& cmdName)
    {
        id = cmdId;
        name = cmdName;
    }
    ~Actions() {}

    void PrintString()
    {
        SOC_PERF_LOGD("Actions-> id: [%{public}d], name: [%{public}s]", id, name.c_str());
        for (auto kv : modeMap) {
            SOC_PERF_LOGD("mode: [%{public}s], cmdid %{public}d", kv.first.c_str(), kv.second);
        }
        for (auto iter = actionList.begin(); iter != actionList.end(); iter++) {
            std::shared_ptr<Action> action = *iter;
            std::string str;
            str.append("variable(").append(std::to_string((int32_t)action->variable.size())).append("): [");
            for (int32_t i = 0; i < (int32_t)action->variable.size(); i++) {
                str.append(std::to_string(action->variable[i])).append(",");
            }
            if (!action->variable.empty()) {
                str.pop_back();
            }
            str.append("]");
            SOC_PERF_LOGD("   duration: [%{public}d], %{public}s", action->duration, str.c_str());
        }
    }
};

class ResAction {
public:
    int64_t value;
    int32_t duration;
    int32_t type;
    int32_t onOff;
    int32_t cmdId;
    int64_t endTime;

public:
    ResAction(int64_t resActionValue, int32_t resActionDuration, int32_t resActionType,
        int32_t resActionOnOff, int32_t resActionCmdId, int64_t resActionEndTime)
    {
        value = resActionValue;
        duration = resActionDuration;
        type = resActionType;
        onOff = resActionOnOff;
        cmdId = resActionCmdId;
        endTime = resActionEndTime;
    }
    ~ResAction() {}

    bool TotalSame(std::shared_ptr<ResAction> resAction)
    {
        if (value == resAction->value
            && duration == resAction->duration
            && type == resAction->type
            && onOff == resAction->onOff
            && cmdId == resAction->cmdId) {
            return true;
        }
        return false;
    }

    bool PartSame(std::shared_ptr<ResAction> resAction)
    {
        if (value == resAction->value
            && duration == resAction->duration
            && type == resAction->type
            && cmdId == resAction->cmdId) {
            return true;
        }
        return false;
    }
};

class ResActionItem {
public:
    ResActionItem(int32_t id)
    {
        resId = id;
    }

    ~ResActionItem() = default;

    int32_t resId;
    std::shared_ptr<ResAction> resAction = nullptr;
    std::shared_ptr<ResActionItem> next = nullptr;
};

class ResStatus {
public:
    std::vector<std::list<std::shared_ptr<ResAction>>> resActionList;
    std::vector<int64_t> candidatesValue;
    std::vector<int64_t> candidatesEndTime;
    int64_t candidate;
    int64_t currentValue;
    int64_t previousValue;
    int64_t currentEndTime;
    int64_t previousEndTime;

public:
    explicit ResStatus(int64_t val)
    {
        resActionList = std::vector<std::list<std::shared_ptr<ResAction>>>(ACTION_TYPE_MAX);
        candidatesValue = std::vector<int64_t>(ACTION_TYPE_MAX);
        candidatesEndTime = std::vector<int64_t>(ACTION_TYPE_MAX);
        candidatesValue[ACTION_TYPE_PERF] = INVALID_VALUE;
        candidatesValue[ACTION_TYPE_POWER] = INVALID_VALUE;
        candidatesValue[ACTION_TYPE_THERMAL] = INVALID_VALUE;
        candidatesValue[ACTION_TYPE_PERFLVL] = INVALID_VALUE;
        candidatesEndTime[ACTION_TYPE_PERF] = MAX_INT_VALUE;
        candidatesEndTime[ACTION_TYPE_POWER] = MAX_INT_VALUE;
        candidatesEndTime[ACTION_TYPE_THERMAL] = MAX_INT_VALUE;
        candidatesEndTime[ACTION_TYPE_PERFLVL] = MAX_INT_VALUE;
        candidate = val;
        currentValue = val;
        previousValue = val;
        currentEndTime = MAX_INT_VALUE;
        previousEndTime = MAX_INT_VALUE;
    }
    ~ResStatus() {}

    std::string ToString()
    {
        std::string str;
        str.append("perf:[");
        for (auto iter = resActionList[ACTION_TYPE_PERF].begin();
            iter != resActionList[ACTION_TYPE_PERF].end(); ++iter) {
            str.append(std::to_string((*iter)->value)).append(",");
        }
        if (!resActionList[ACTION_TYPE_PERF].empty()) {
            str.pop_back();
        }
        str.append("]power:[");
        for (auto iter = resActionList[ACTION_TYPE_POWER].begin();
            iter != resActionList[ACTION_TYPE_POWER].end(); ++iter) {
            str.append(std::to_string((*iter)->value)).append(",");
        }
        if (!resActionList[ACTION_TYPE_POWER].empty()) {
            str.pop_back();
        }
        str.append("]thermal:[");
        for (auto iter = resActionList[ACTION_TYPE_THERMAL].begin();
            iter != resActionList[ACTION_TYPE_THERMAL].end(); ++iter) {
            str.append(std::to_string((*iter)->value)).append(",");
        }
        if (!resActionList[ACTION_TYPE_THERMAL].empty()) {
            str.pop_back();
        }
        str.append("]candidatesValue[");
        for (auto iter = candidatesValue.begin(); iter != candidatesValue.end(); ++iter) {
            str.append(std::to_string(*iter)).append(",");
        }
        str.pop_back();
        str.append("]candidate[").append(std::to_string(candidate));
        str.append("]currentValue[").append(std::to_string(currentValue)).append("]");
        return str;
    }
};

static inline int64_t Max(int64_t num1, int64_t num2)
{
    if (num1 >= num2) {
        return num1;
    }
    return num2;
}

static inline int64_t Max(int64_t num1, int64_t num2, int64_t num3)
{
    return Max(Max(num1, num2), num3);
}

static inline int64_t Min(int64_t num1, int64_t num2)
{
    if (num1 <= num2) {
        return num1;
    }
    return num2;
}

static inline int64_t Min(int64_t num1, int64_t num2, int64_t num3)
{
    return Min(Min(num1, num2), num3);
}

static inline bool IsNumber(const std::string& str)
{
    for (int32_t i = 0; i < (int32_t)str.size(); i++) {
        if (i == 0 && str.at(i) == '-') {
            continue;
        }
        if (str.at(i) < '0' || str.at(i) > '9') {
            return false;
        }
    }
    return true;
}

static inline bool IsValidRangeResId(int32_t id)
{
    if (id < MIN_RESOURCE_ID || id > MAX_RESOURCE_ID) {
        return false;
    }
    return true;
}

static inline bool IsValidPersistMode(int32_t persistMode)
{
    if (persistMode != WRITE_NODE && persistMode != REPORT_TO_PERFSO) {
        return false;
    }
    return true;
}

static std::vector<std::string> SplitEx(const std::string& str, const std::string& pattern)
{
    int32_t position;
    std::vector<std::string> result;
    std::string tempStr = str;
    tempStr += pattern;
    int32_t length = (int32_t)tempStr.size();
    for (int32_t i = 0; i < length; i++) {
        position = (int32_t)tempStr.find(pattern, i);
        if (position < length) {
            std::string tmp = tempStr.substr(i, position - i);
            result.push_back(tmp);
            i = position + (int32_t)pattern.size() - 1;
        }
    }
    return result;
}

static inline std::vector<std::string> Split(const std::string& str, const std::string& pattern)
{
    return SplitEx(str, pattern);
}

} // namespace SOCPERF
} // namespace OHOS

#endif // SOC_PERF_SERVICES_CORE_INCLUDE_COMMON_H
