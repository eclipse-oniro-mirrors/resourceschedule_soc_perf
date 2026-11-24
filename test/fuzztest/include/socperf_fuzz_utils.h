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

#ifndef FOUNDATION_RESOURCESCHEDULE_SOCPERF_TEST_FUZZTEST_INCLUDE_SOCPERF_FUZZ_UTILS_H
#define FOUNDATION_RESOURCESCHEDULE_SOCPERF_TEST_FUZZTEST_INCLUDE_SOCPERF_FUZZ_UTILS_H

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>

namespace OHOS {
namespace SOCPERF {
// Synthetic resource ids shared by the soc_perf fuzz targets.
constexpr int32_t FUZZ_RES_ID_CPU_MAX = 1000;
constexpr int32_t FUZZ_RES_ID_CPU_MIN = 1001;
constexpr int32_t FUZZ_RES_ID_CPU_GOV = 1002;
constexpr int32_t FUZZ_RES_ID_GPU_FREQ = 1003;
constexpr int32_t FUZZ_RES_ID_UNKNOWN = 9999;

// Synthetic command ids shared by the fuzz configs.
constexpr int32_t FUZZ_CMD_ID_PERF = 20000;
constexpr int32_t FUZZ_CMD_ID_LONG_PERF = 20001;
constexpr int32_t FUZZ_CMD_ID_THERMAL_PERF = 20002;
constexpr int32_t FUZZ_CMD_ID_WEAK_PERF = 21000;
constexpr int32_t FUZZ_CMD_ID_WEAK_POWER = 21001;
constexpr int32_t FUZZ_CMD_ID_WEAK_THERMAL = 21002;
constexpr int32_t FUZZ_CMD_ID_LIMIT = 30000;
constexpr int32_t FUZZ_CMD_ID_LIMIT_LEVEL = 30001;
constexpr int32_t FUZZ_CMD_ID_ALIVE_PERF = 50000;

// Frequency and governor values used by the synthetic resource nodes.
constexpr int32_t FUZZ_FREQ_CPU_LOW = 100;
constexpr int32_t FUZZ_FREQ_CPU_MID = 200;
constexpr int32_t FUZZ_FREQ_CPU_HIGH = 300;
constexpr int32_t FUZZ_FREQ_GPU_MID = 400;
constexpr int32_t FUZZ_FREQ_GPU_HIGH = 500;
constexpr int32_t FUZZ_GOV_PERFORMANCE = 2;

// Maximum length of random text consumed from the fuzz input.
constexpr size_t FUZZ_RANDOM_TEXT_MAX_LEN = 32;

class FuzzDataProvider {
public:
    FuzzDataProvider(const uint8_t* data, size_t size) : data_(data), size_(size), offset_(0) {}
    ~FuzzDataProvider() = default;

    template<typename T>
    T ConsumeIntegral(T fallback = 0)
    {
        if (data_ == nullptr || offset_ + sizeof(T) > size_) {
            return fallback;
        }
        T value {};
        std::copy_n(data_ + offset_, sizeof(T), reinterpret_cast<uint8_t*>(&value));
        offset_ += sizeof(T);
        return value;
    }

    bool ConsumeBool()
    {
        return (ConsumeIntegral<uint8_t>(0) & 0x1) != 0;
    }

    uint8_t ConsumeByte()
    {
        return ConsumeIntegral<uint8_t>(0);
    }

    int32_t ConsumeInt32(int32_t fallback = 0)
    {
        return ConsumeIntegral<int32_t>(fallback);
    }

    int64_t ConsumeInt64(int64_t fallback = 0)
    {
        return ConsumeIntegral<int64_t>(fallback);
    }

    int32_t ConsumeInt32InRange(int32_t minValue, int32_t maxValue)
    {
        if (minValue > maxValue) {
            std::swap(minValue, maxValue);
        }
        if (minValue == maxValue) {
            return minValue;
        }
        uint64_t span = static_cast<uint64_t>(static_cast<int64_t>(maxValue) -
            static_cast<int64_t>(minValue) + 1);
        return minValue + static_cast<int32_t>(ConsumeIntegral<uint32_t>(0) % span);
    }

    size_t ConsumeSize(size_t maxValue)
    {
        if (maxValue == 0) {
            return 0;
        }
        return static_cast<size_t>(ConsumeIntegral<uint32_t>(0) % (maxValue + 1));
    }

    std::string ConsumeString(size_t maxLen)
    {
        if (maxLen == 0 || RemainingBytes() == 0) {
            return "";
        }
        size_t len = std::min(RemainingBytes(), maxLen);
        size_t actualLen = ConsumeSize(len);
        if (actualLen == 0 || offset_ + actualLen > size_) {
            return "";
        }
        std::string value(reinterpret_cast<const char*>(data_ + offset_), actualLen);
        offset_ += actualLen;
        return value;
    }

    size_t RemainingBytes() const
    {
        return (offset_ >= size_) ? 0 : (size_ - offset_);
    }

private:
    const uint8_t* data_;
    size_t size_;
    size_t offset_;
};

class ScopedTempFile {
public:
    ScopedTempFile(const std::string& prefix, const std::string& content)
    {
        std::string pattern = "/tmp/" + (prefix.empty() ? "socperf" : prefix) + "_XXXXXX";
        std::vector<char> buffer(pattern.begin(), pattern.end());
        buffer.push_back('\0');
        fd_ = mkstemp(buffer.data());
        if (fd_ < 0) {
            return;
        }
        path_ = buffer.data();
        WriteAll(content);
        lseek(fd_, 0, SEEK_SET);
    }

    ~ScopedTempFile()
    {
        if (fd_ >= 0) {
            close(fd_);
            fd_ = -1;
        }
        if (!path_.empty()) {
            unlink(path_.c_str());
        }
    }

    bool IsValid() const
    {
        return fd_ >= 0 && !path_.empty();
    }

    const std::string& GetPath() const
    {
        return path_;
    }

private:
    void WriteAll(const std::string& content)
    {
        if (fd_ < 0) {
            return;
        }
        size_t written = 0;
        while (written < content.size()) {
            ssize_t ret = write(fd_, content.data() + written, content.size() - written);
            if (ret <= 0) {
                break;
            }
            written += static_cast<size_t>(ret);
        }
    }

    int fd_ = -1;
    std::string path_;
};
} // namespace SOCPERF
} // namespace OHOS

#endif // FOUNDATION_RESOURCESCHEDULE_SOCPERF_TEST_FUZZTEST_INCLUDE_SOCPERF_FUZZ_UTILS_H
