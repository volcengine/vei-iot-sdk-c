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

#ifndef ARENAL_IOT_LOG_REPORT_HEADER_H
#define ARENAL_IOT_LOG_REPORT_HEADER_H

#include "core/iot_core_header.h"

typedef struct log_handler {
    iot_mqtt_ctx_t *mqtt_handle;
    struct aws_allocator *allocator;
    bool log_report_switch;
    struct aws_mutex lock;
    enum aiot_log_level lowest_level; // 最新上报level
    struct aws_hash_table stream_id_config_map;

} log_handler_t;

typedef struct local_log_config{
    char *traceId;
    char *contentKeyword;
    char *type;
    struct aws_byte_cursor type_cur;
    enum aiot_log_level logLevel;
    uint64_t start_time;
    uint64_t start_date_time;
    uint64_t endTime;
    int64_t offset;
    int32_t count;
} local_log_config_t;

typedef struct {
    struct aws_string *traceId;
    bool log_report_switch;
    char *contentKeyword;
    char *type;
    struct aws_byte_cursor type_cur;
    enum aiot_log_level logLevel;
    uint64_t start_time;
    uint64_t start_date_time;
} stream_log_config_t;

typedef struct {
    log_handler_t *log_handler;
    struct aws_array_list *pending_log_lines;
} stream_map_foreach_ctx_t;

static void s_stream_log_report(log_handler_t *log_handler, struct aws_array_list *pending_log_lines);

static void s_stream_log_config_release(stream_log_config_t *log_config);

static void s_stream_id_config_map_callback_value_destroy_fn(void *value);

static void s_stream_log_report(log_handler_t *log_handler, struct aws_array_list *pending_log_lines);

static void s_common_log_report(log_handler_t *log_handler, struct aws_array_list *pending_log_lines);

static void s_log_report_on_log_save_fn(struct aws_array_list *log_lines, void *userdata);

static void s_sub_log_report_config_topic(log_handler_t *handler);

static void s_log_rev_log_report_config(struct aws_mqtt_client_connection *connection,
                                        const struct aws_byte_cursor *topic,
                                        const struct aws_byte_cursor *payload,
                                        bool dup,
                                        enum aws_mqtt_qos qos,
                                        bool retain,
                                        void *userdata);


static void s_sub_stream_log_config_topic(log_handler_t *handler);

static void s_log_rev_stream_log_config(struct aws_mqtt_client_connection *connection,
                                        const struct aws_byte_cursor *topic,
                                        const struct aws_byte_cursor *payload,
                                        bool dup,
                                        enum aws_mqtt_qos qos,
                                        bool retain,
                                        void *userdata);

static void s_sub_local_log_config_topic(log_handler_t *handler);

static void s_log_local_log_config(struct aws_mqtt_client_connection *connection,
                                   const struct aws_byte_cursor *topic,
                                   const struct aws_byte_cursor *payload,
                                   bool dup,
                                   enum aws_mqtt_qos qos,
                                   bool retain,
                                   void *userdata);

#endif // ARENAL_IOT_LOG_REPORT_HEADER_H