/*
 * Copyright 2022-2024 Beijing Volcano Engine Technology Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ARENAL_IOT_IOT_LOG_H
#define ARENAL_IOT_IOT_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

#define LOG_TYPE_SDK  "sdk"
#define LOG_TYPE_DEVICE "device"

enum aiot_log_level {
    NONE,
    FATAL,
    ERROR,
    WARN,
    INFO,
    DEBUG,
    COUNT,
};


#define LOGF(tag, ...) sdk_log_print(FATAL, LOG_TYPE_SDK, tag,__VA_ARGS__)
#define LOGE(tag, ...) sdk_log_print(ERROR,LOG_TYPE_SDK, tag,__VA_ARGS__)
#define LOGW(tag, ...) sdk_log_print(WARN,LOG_TYPE_SDK, tag,__VA_ARGS__)
#define LOGI(tag, ...) sdk_log_print(INFO,LOG_TYPE_SDK, tag,__VA_ARGS__)
#define LOGD(tag, ...) sdk_log_print(DEBUG,LOG_TYPE_SDK, tag,__VA_ARGS__)


#define DEVICE_LOGF(tag, ...) sdk_log_print(FATAL,LOG_TYPE_DEVICE, tag,__VA_ARGS__)
#define DEVICE_LOGE(tag, ...) sdk_log_print(ERROR,LOG_TYPE_DEVICE, tag,__VA_ARGS__)
#define DEVICE_LOGW(tag, ...) sdk_log_print(WARN,LOG_TYPE_DEVICE, tag,__VA_ARGS__)
#define DEVICE_LOGI(tag, ...) sdk_log_print(INFO,LOG_TYPE_DEVICE, tag,__VA_ARGS__)
#define DEVICE_LOGD(tag, ...) sdk_log_print(DEBUG,LOG_TYPE_DEVICE, tag,__VA_ARGS__)


struct iot_log_ctx_option {
    // 日志写入文件的时间间隔
    int32_t check_write_file_line_count;

    // 日志写入文件的触发 行数阈值, 超过这个阈值 则写入到文件
    int32_t check_write_file_interval_sec;
};

void sdk_log_print(enum aiot_log_level level, const char *logType, const char *tag, const char *format, ...);

struct iot_log_obj {
    uint64_t time;
    const char *logLevelStr;
    enum aiot_log_level log_level;
    const char *logType;
    struct aws_string *logContent;
};


void iot_log_init(char *save_dir_path);

void iot_log_init_with_option(char *save_dir_path, struct iot_log_ctx_option option);

char *iot_get_log_file_dir();

void iot_log_release();


#endif //ARENAL_IOT_IOT_LOG_H
