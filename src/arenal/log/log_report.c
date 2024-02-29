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

#include <core/iot_mqtt.h>
#include <core/iot_log.h>
#include <core/iot_core_header.h>
#include <thing_model/iot_tm_api.h>
#include <thing_model/iot_tm_header.h>
#include <aws/common/json.h>
#include <aws/common/file.h>
#include "log_report.h"
#include "core/iot_util.h"
#include "log_report_header.h"

// 实时流 超时时间
#define STREAM_LOG_TIME_OUT_MIL 3 * 60 * 60 * 1000

log_handler_t *aiot_log_init(void) {
    log_handler_t *log_handler = aws_mem_acquire(get_iot_core_context()->alloc, sizeof(log_handler_t));
    AWS_ZERO_STRUCT(*log_handler);
    log_handler->allocator = get_iot_core_context()->alloc;
    log_handler->log_report_switch = false;
    log_handler->lowest_level = DEBUG;
    aws_hash_table_init(&log_handler->stream_id_config_map, log_handler->allocator,
                        10, aws_hash_string, aws_hash_callback_string_eq,
                        NULL, s_stream_id_config_map_callback_value_destroy_fn);
    aws_mutex_init(&log_handler->lock);
    iot_log_set_on_log_save_fn(s_log_report_on_log_save_fn, log_handler);
    return log_handler;
}


void aiot_log_set_mqtt_handler(log_handler_t *handle, iot_mqtt_ctx_t *mqtt_handle) {
    handle->mqtt_handle = mqtt_handle;
    s_sub_log_report_config_topic(handle);
    s_sub_stream_log_config_topic(handle);
    s_sub_local_log_config_topic(handle);
}


void aiot_log_set_report_switch(log_handler_t *handle, bool is_upload_log, enum aiot_log_level lowest_level) {
    handle->lowest_level = lowest_level;
    handle->log_report_switch = is_upload_log;
}


// 日志流处理
void s_log_report_on_log_save_fn(struct aws_array_list *log_lines, void *userdata) {
    // 普通日志上报
    log_handler_t *log_handler = (log_handler_t *) userdata;
    aws_mutex_try_lock(&log_handler->lock);
    s_common_log_report(log_handler, log_lines);
    s_stream_log_report(log_handler, log_lines);
    aws_mutex_unlock(&log_handler->lock);
}


static void s_stream_id_config_map_callback_value_destroy_fn(void *value) {
    stream_log_config_t *log_config = value;
    s_stream_log_config_release(log_config);
}

static void s_stream_log_config_release(stream_log_config_t *log_config) {
    aws_string_destroy_secure(log_config->traceId);
    aws_mem_release(get_iot_core_context()->alloc, log_config->contentKeyword);
    aws_mem_release(get_iot_core_context()->alloc, log_config->type);
    aws_mem_release(get_iot_core_context()->alloc, log_config);
}

static int s_foreach_stream_id_config_map_upload_log(void *context, struct aws_hash_element *p_element) {
    stream_map_foreach_ctx_t *ctx = context;
    log_handler_t *log_handler = ctx->log_handler;
    struct aws_array_list *pending_log_lines = ctx->pending_log_lines;
    stream_log_config_t *log_config = p_element->value;
    if (get_current_time_mil() - log_config->start_time > STREAM_LOG_TIME_OUT_MIL) {
        s_stream_log_config_release(log_config);
        // 这里不会自动删除 item  不会回调  s_stream_id_config_map_callback_value_destroy_fn 所以需要手动 release
        return AWS_COMMON_HASH_TABLE_ITER_DELETE;
    }


    if (log_config->log_report_switch != true) {
        return AWS_COMMON_HASH_TABLE_ITER_CONTINUE;
    }

    struct aws_json_value *logReportJson = aws_json_value_new_object(log_handler->allocator);

    char *id_string = get_random_string_with_time_suffix(log_handler->allocator);
    aws_json_add_str_val_1(log_handler->allocator, logReportJson, "id", id_string);
    aws_mem_release(log_handler->allocator, id_string);


    aws_json_add_str_val_1(log_handler->allocator, logReportJson, "version", SDK_VERSION);
    struct aws_json_value *data = aws_json_value_new_array(log_handler->allocator);
    size_t line_count = aws_array_list_length(pending_log_lines);
    int real_count = 0;

    for (size_t i = 0; i < line_count; ++i) {
        struct iot_log_obj *logObj = NULL;
        AWS_FATAL_ASSERT(aws_array_list_get_at(pending_log_lines, &logObj, i) == AWS_OP_SUCCESS);
        if (logObj == NULL) {
            continue;
        }

        if (logObj->log_level > log_config->logLevel) {
            // 不符合要求的 日志 不需要
            continue;
        }

        if (log_config->contentKeyword != NULL && strlen(log_config->contentKeyword) > 0) {
            char *find_str = strstr(aws_string_c_str(logObj->logContent), log_config->contentKeyword);
            if (find_str == NULL) {
                continue;
            }
        }

        if (log_config->type_cur.len > 0) {
            struct aws_byte_cursor log_type = aws_byte_cursor_from_c_str(logObj->logType);
            if (aws_byte_cursor_eq_ignore_case(&log_config->type_cur, &log_type) != true) {
                continue;
            }
        }

        real_count++;
        struct aws_json_value *iten_json = aws_json_value_new_object(log_handler->allocator);
        aws_json_add_num_val1(log_handler->allocator, iten_json, "CreateTime", logObj->time);
        aws_json_add_str_val_1(log_handler->allocator, iten_json, "LogLevel", logObj->logLevelStr);
        aws_json_add_str_val_1(log_handler->allocator, iten_json, "Type", logObj->logType);
        aws_json_add_aws_string_val1(log_handler->allocator, iten_json, "Content", logObj->logContent);
        aws_json_value_add_array_element(data, iten_json);
    }

    if (real_count <= 0) {
        // 没有符合要求的日志,  忽略此次上报
        aws_json_value_destroy(logReportJson);
        return AWS_COMMON_HASH_TABLE_ITER_CONTINUE;
    }

    aws_json_value_add_to_object(logReportJson, aws_byte_cursor_from_c_str("data"), data);
    struct aws_byte_buf payload_buf = aws_json_obj_to_bye_buf(log_handler->allocator, data);
    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_buf(&payload_buf);

    char *topic = iot_get_topic_with_1_param(log_handler->allocator, "sys/%s/%s/log/stream/report/%s",
                                             log_handler->mqtt_handle->product_key,
                                             log_handler->mqtt_handle->device_name,
                                             log_config->traceId
    );
    struct aws_byte_cursor public_topic = aws_byte_cursor_from_c_str(topic);

    printf("public_topic = %s\n", public_topic.ptr);
    printf("payload_cur = %s\n", payload_cur.ptr);
    aws_mqtt_client_connection_publish(log_handler->mqtt_handle->mqtt_connection, &public_topic,
                                       AWS_MQTT_QOS_AT_MOST_ONCE, false, &payload_cur,
                                       _tm_mqtt_post_on_complete_fn, NULL);

    aws_byte_buf_clean_up(&payload_buf);
    aws_json_value_destroy(logReportJson);
    aws_mem_release(log_handler->allocator, topic);
    return AWS_COMMON_HASH_TABLE_ITER_CONTINUE;
}


static void s_stream_log_report(log_handler_t *log_handler, struct aws_array_list *pending_log_lines) {
    // 遍历 list
    stream_map_foreach_ctx_t ctx = {
            .log_handler = log_handler,
            .pending_log_lines = pending_log_lines
    };
    aws_hash_table_foreach(&log_handler->stream_id_config_map, s_foreach_stream_id_config_map_upload_log, &ctx);
}


// 上报 日志
static void s_common_log_report(log_handler_t *log_handler, struct aws_array_list *pending_log_lines) {
    if (log_handler->log_report_switch != true) {
        // 开关开启
        return;
    }

    struct aws_json_value *logReportJson = aws_json_value_new_object(log_handler->allocator);

    char *id_string = get_random_string_with_time_suffix(log_handler->allocator);
    aws_json_add_str_val_1(log_handler->allocator, logReportJson, "id", id_string);
    aws_mem_release(log_handler->allocator, id_string);


    aws_json_add_str_val_1(log_handler->allocator, logReportJson, "version", SDK_VERSION);
    struct aws_json_value *data = aws_json_value_new_array(log_handler->allocator);
    size_t line_count = aws_array_list_length(pending_log_lines);
    int real_count = 0;

    for (size_t i = 0; i < line_count; ++i) {
        struct iot_log_obj *logObj = NULL;
        AWS_FATAL_ASSERT(aws_array_list_get_at(pending_log_lines, &logObj, i) == AWS_OP_SUCCESS);
        if (logObj == NULL) {
            continue;
        }

        if (logObj->log_level > log_handler->lowest_level) {
            // 不符合要求的 日志 不需要
            continue;
        }

        real_count++;
        struct aws_json_value *iten_json = aws_json_value_new_object(log_handler->allocator);
        aws_json_add_num_val1(log_handler->allocator, iten_json, "CreateTime", logObj->time);
        aws_json_add_str_val_1(log_handler->allocator, iten_json, "LogLevel", logObj->logLevelStr);
        aws_json_add_str_val_1(log_handler->allocator, iten_json, "Type", logObj->logType);
        aws_json_add_aws_string_val1(log_handler->allocator, iten_json, "Content", logObj->logContent);
        aws_json_value_add_array_element(data, iten_json);
    }


    if (real_count <= 0) {
        // 没有符合要求的日志,  忽略此次上报
        aws_json_value_destroy(logReportJson);
        return;
    }

    aws_json_value_add_to_object(logReportJson, aws_byte_cursor_from_c_str("data"), data);
    struct aws_byte_buf payload_buf = aws_json_obj_to_bye_buf(log_handler->allocator, logReportJson);
    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_buf(&payload_buf);


    char *topic = iot_get_common_topic(log_handler->allocator, "sys/%s/%s/log/batch/report", log_handler->mqtt_handle->product_key, log_handler->mqtt_handle->device_name);
    struct aws_byte_cursor public_topic = aws_byte_cursor_from_c_str(topic);

    aws_mqtt_client_connection_publish(log_handler->mqtt_handle->mqtt_connection, &public_topic,
                                       AWS_MQTT_QOS_AT_MOST_ONCE, false, &payload_cur,
                                       _tm_mqtt_post_on_complete_fn, NULL);

    aws_byte_buf_clean_up(&payload_buf);
    aws_json_value_destroy(logReportJson);
    aws_mem_release(log_handler->allocator, topic);


}


static void s_sub_log_report_config_topic(log_handler_t *handler) {
    log_handler_t *log_handle = (log_handler_t *) handler;
    if (log_handle->mqtt_handle == NULL) {
        return;
    }
    char *topic = iot_get_common_topic(log_handle->allocator, "sys/%s/%s/log/batch/config", log_handle->mqtt_handle->product_key, log_handle->mqtt_handle->device_name);
    iot_mqtt_sub(log_handle->mqtt_handle, topic, 1, s_log_rev_log_report_config, log_handle);
    aws_mem_release(log_handle->allocator, topic);

}

static void s_log_rev_log_report_config(struct aws_mqtt_client_connection *connection,
                                        const struct aws_byte_cursor *topic,
                                        const struct aws_byte_cursor *payload,
                                        bool dup,
                                        enum aws_mqtt_qos qos,
                                        bool retain,
                                        void *userdata) {
    LOGD(TAG_IOT_MQTT, "s_log_rev_log_report_config call topic = %.*s,  payload = %.*s", AWS_BYTE_CURSOR_PRI(*topic), AWS_BYTE_CURSOR_PRI(*payload));
//    {"id":"a6b7c2dd221209150431","version":"1.0","data":{"Switch":true,"LowestLevel":"debug"}}

    log_handler_t *log_handler = (log_handler_t *) userdata;
    aws_mutex_try_lock(&log_handler->lock);

    struct aws_json_value *payload_json = aws_json_value_new_from_string(log_handler->allocator, *payload);
    struct aws_json_value *data_json = aws_json_value_get_from_object(payload_json, aws_byte_cursor_from_c_str("data"));
    bool log_switch = aws_json_get_bool_val(data_json, "Switch");
    LOGD(TAG_IOT_MQTT, "s_log_rev_log_report_config call log_switch = %d ", log_switch);
    log_handler->log_report_switch = log_switch;
    struct aws_byte_cursor lowest_level_cur = aws_json_get_str_byte_cur_val(payload_json, "LowestLevel");
    log_handler->lowest_level = (enum aiot_log_level) _log_string_to_level(&lowest_level_cur);

    aws_json_value_destroy(payload_json);
    aws_mutex_unlock(&log_handler->lock);
}


static void s_sub_stream_log_config_topic(log_handler_t *handler) {
    log_handler_t *log_handle = (log_handler_t *) handler;
    if (log_handle->mqtt_handle == NULL) {
        return;
    }
    char *topic = iot_get_common_topic(log_handle->allocator, "sys/%s/%s/log/stream/config/+", log_handle->mqtt_handle->product_key, log_handle->mqtt_handle->device_name);
    iot_mqtt_sub(log_handle->mqtt_handle, topic, 1, s_log_rev_stream_log_config, handler);
    aws_mem_release(log_handle->allocator, topic);

}

static void s_log_rev_stream_log_config(struct aws_mqtt_client_connection *connection,
                                        const struct aws_byte_cursor *topic,
                                        const struct aws_byte_cursor *payload,
                                        bool dup,
                                        enum aws_mqtt_qos qos,
                                        bool retain,
                                        void *userdata) {
    LOGD(TAG_IOT_MQTT, "s_log_rev_stream_log_config call topic = %.*s,  payload = %.*s", AWS_BYTE_CURSOR_PRI(*topic), AWS_BYTE_CURSOR_PRI(*payload));

    log_handler_t *log_handler = (log_handler_t *) userdata;
    struct aws_json_value *payload_json = aws_json_value_new_from_string(log_handler->allocator, *payload);

    stream_log_config_t *log_config = aws_mem_calloc(log_handler->allocator, 1, sizeof(stream_log_config_t));
    log_config->traceId = aws_json_get_string_val(payload_json, "id");
    struct aws_json_value *data_json = aws_json_value_get_from_object(payload_json, aws_byte_cursor_from_c_str("data"));
    log_config->log_report_switch = aws_json_get_bool_val(data_json, "Switch");


    if (log_config->log_report_switch != true) {
        aws_hash_table_remove(&log_handler->stream_id_config_map, log_config->traceId, NULL, NULL);
        aws_json_value_destroy(payload_json);
        return;
    }

    log_config->contentKeyword = aws_json_get_str(log_handler->allocator, data_json, "ContentKeyword");
    log_config->type = aws_json_get_str(log_handler->allocator, data_json, "Type");
    log_config->type_cur = aws_byte_cursor_from_c_str(log_config->type);
    struct aws_byte_cursor log_level_cur = aws_json_get_str_byte_cur_val(data_json, "LogLevel");
    log_config->logLevel = _log_string_to_level(&log_level_cur);
    log_config->start_time = (int64_t) aws_json_get_num_val(data_json, "StartTime");
    aws_hash_table_put(&log_handler->stream_id_config_map, log_config->traceId, log_config, NULL);
    aws_json_value_destroy(payload_json);

//    aws_hash_table_remove(&log_handler->stream_id_config_map, log_config->traceId, NULL, NULL);


}

static void s_sub_local_log_config_topic(log_handler_t *handler) {
    log_handler_t *log_handle = (log_handler_t *) handler;
    if (log_handle->mqtt_handle == NULL) {
        return;
    }
    char *topic = iot_get_common_topic(log_handle->allocator, "sys/%s/%s/log/local/config/+", log_handle->mqtt_handle->product_key, log_handle->mqtt_handle->device_name);
    iot_mqtt_sub(log_handle->mqtt_handle, topic, 1, s_log_local_log_config, handler);
    aws_mem_release(log_handle->allocator, topic);
}


static void s_log_local_log_config(struct aws_mqtt_client_connection *connection,
                                   const struct aws_byte_cursor *topic,
                                   const struct aws_byte_cursor *payload,
                                   bool dup,
                                   enum aws_mqtt_qos qos,
                                   bool retain,
                                   void *userdata) {
    LOGD(TAG_IOT_MQTT, "s_log_local_log_config call topic = %.*s,  payload = %.*s", AWS_BYTE_CURSOR_PRI(*topic), AWS_BYTE_CURSOR_PRI(*payload));
    // 回捞一定范围内的日志
//    {"id":"2022120915052001017425518101E4C895","version":"1.0","data":{"ContentKeyword":"","Type":"","LogLevel":"","StartTime":1669878317000,"EndTime":1670655918000,"Offset":0,"Count":10}}

    log_handler_t *log_handler = (log_handler_t *) userdata;
    struct aws_json_value *payload_json = aws_json_value_new_from_string(log_handler->allocator, *payload);

    local_log_config_t localLogConfig = {0};
    localLogConfig.traceId = aws_json_get_str(log_handler->allocator, payload_json, "id");
    struct aws_json_value *data_json = aws_json_value_get_from_object(payload_json, aws_byte_cursor_from_c_str("data"));
    localLogConfig.contentKeyword = aws_json_get_str(log_handler->allocator, data_json, "ContentKeyword");
    localLogConfig.type = aws_json_get_str(log_handler->allocator, data_json, "Type");
    localLogConfig.type_cur = aws_json_get_str_byte_cur_val(data_json, "Type");
    struct aws_byte_cursor log_level_cur = aws_json_get_str_byte_cur_val(data_json, "LogLevel");
    localLogConfig.logLevel = _log_string_to_level(&log_level_cur);
    localLogConfig.start_time = (int64_t) aws_json_get_num_val(data_json, "StartTime");
    localLogConfig.endTime = (int64_t) aws_json_get_num_val(data_json, "EndTime");
    localLogConfig.offset = (int64_t) aws_json_get_num_val(data_json, "Offset");
    localLogConfig.count = (int32_t) aws_json_get_num_val(data_json, "Count");
    localLogConfig.start_date_time = aws_date_to_short_utc_time_mil(localLogConfig.start_time);


    struct aws_string *log_dir_path = aws_string_new_from_c_str(log_handler->allocator, iot_get_log_file_dir());
    if (log_dir_path == NULL) {
        return;
    }
    struct aws_directory_iterator *iterator = aws_directory_entry_iterator_new(log_handler->allocator, log_dir_path);
    if (iterator == NULL) {
        return;
    }

    int total_count = 0;
    size_t totalOffset = 0;
    size_t nextOffset = localLogConfig.offset;
    ssize_t total_read_file_size;
    struct aws_json_value *log_list_json = aws_json_value_new_array(log_handler->allocator);
    do {
        if (localLogConfig.start_time == 0 || localLogConfig.endTime == 0) {
            break;
        }
        const struct aws_directory_entry *entry = aws_directory_entry_iterator_get_value(iterator);
        if (entry->file_type == AWS_FILE_TYPE_FILE) {
            struct aws_string *file_path_string = aws_string_new_from_cursor(log_handler->allocator, &entry->path);
            char *file_path_str = aws_string_c_str(file_path_string);

            char *file_name = strrchr(file_path_str, AWS_PATH_DELIM);
            if (str_end_with(file_name, ".log") != 0) {
                continue;
            }

            char file_date_str[30] = {0};
            strncpy(file_date_str, file_name + 5, strlen(file_name) - 9);
            uint64_t time = aws_date_to_utc_time_mil(file_date_str);

            // 跳过offset不符的文件
            // 开始时间需要转成日期的格式.

            if (entry->file_size < nextOffset) {
                // 这个文件直接忽略
                nextOffset -= entry->file_size;
                totalOffset += entry->file_size;
                continue;
            }

            if (time >= localLogConfig.start_date_time && time <= localLogConfig.endTime) {
                // 读取文件
                FILE *fp = aws_fopen(aws_string_c_str(file_path_string), "r");
                char *line = NULL;
                size_t len = 0;
                ssize_t read;
                ssize_t read_file_size;
                while ((read = getline(&line, &len, fp)) != -1) {
                    read_file_size += read;
                    if (nextOffset > 0) {
                        if (read_file_size < nextOffset) {
                            // 前 offset 字节的数据 过滤掉
                            continue;
                        } else {
                            // 无需在移动字节数了, 到了指定位置
                            nextOffset = 0;
                        }
                    }
                    // 读到的有效字节数
                    total_read_file_size += read;

                    if (strlen(line) < 50) {
                        // 长度小于日志规范 忽略
                        continue;
                    }
                    int type_left_index = get_string_index_by_times(line, '[', 1);
                    int type_right_index = get_string_index_by_times(line, ']', 1);
                    if (type_right_index <= 0) {
                        // 找不到正确的 ']' 不符合规范的日志忽略
                        continue;
                    }

                    char type_str[30] = {0};
                    strncpy(type_str, line + type_left_index + 1, type_right_index - type_left_index - 1);
                    struct aws_byte_cursor type_cur = aws_byte_cursor_from_c_str(type_str);
                    if (localLogConfig.type_cur.len > 0) {
                        if (aws_byte_cursor_eq_ignore_case(&type_cur, &type_str) != true) {
                            continue;
                        }
                    }

                    int log_level_left_index = get_string_index_by_times(line, '[', 2);
                    int log_level_right_index = get_string_index_by_times(line, ']', 2);

                    if (log_level_left_index <= 0 || log_level_right_index <= 0) {
                        // 找不到正确的 ']' 不符合规范的日志忽略
                        continue;
                    }

                    char log_level_str[30] = {0};
                    strncpy(log_level_str, line + log_level_left_index + 1, log_level_right_index - log_level_left_index - 1);

                    struct aws_byte_cursor log_level_cur = aws_byte_cursor_from_c_str(log_level_str);
                    enum aiot_log_level log_level = _log_string_to_level(&log_level_cur);
                    if (log_level > localLogConfig.logLevel) {
                        continue;
                    }

                    int time_left_index = get_string_index_by_times(line, '[', 3);
                    int time_right_index = get_string_index_by_times(line, ']', 3);
                    if (time_left_index <= 0 || time_right_index <= 0) {
                        // 找不到正确的 ']' 不符合规范的日志忽略
                        continue;
                    }

                    char time_str[30] = {0};
                    strncpy(time_str, line + time_left_index + 1, time_right_index - time_left_index - 1);
                    uint64_t log_time_mil = aws_date_to_utc_time_mil(time_str);

                    if (log_time_mil < localLogConfig.start_time || time > localLogConfig.endTime) {
                        continue;
                    }

                    if (localLogConfig.contentKeyword != NULL && strlen(localLogConfig.contentKeyword) > 0) {
                        char *find_str = strstr(line, localLogConfig.contentKeyword);
                        if (find_str == NULL) {
                            continue;
                        }

                    }


                    total_count++;

                    struct aws_json_value *iten_json = aws_json_value_new_object(log_handler->allocator);
                    aws_json_add_num_val1(log_handler->allocator, iten_json, "CreateTime", log_time_mil);
                    aws_json_add_str_val_1(log_handler->allocator, iten_json, "LogLevel", log_level_str);
                    aws_json_add_str_val_1(log_handler->allocator, iten_json, "Type", type_str);
                    aws_json_add_str_val_1(log_handler->allocator, iten_json, "Content", line);
                    aws_json_value_add_array_element(log_list_json, iten_json);

                    if (total_count >= localLogConfig.count) {
                        break;
                    }
                }
                if (line) {
                    free(line);
                }
            }
            totalOffset += total_read_file_size;
            if (total_count >= localLogConfig.count) {
                break;
            }
        }
    } while (aws_directory_entry_iterator_next(iterator) == AWS_OP_SUCCESS);


    struct aws_json_value *logReportJson = aws_json_value_new_object(log_handler->allocator);
    aws_json_add_str_val_1(log_handler->allocator, logReportJson, "id", localLogConfig.traceId);
    aws_json_add_str_val_1(log_handler->allocator, logReportJson, "version", SDK_VERSION);

    struct aws_json_value *result_data_json = aws_json_value_new_object(log_handler->allocator);
    uint64_t return_offset = total_count;
    if (total_count > 0) {
        return_offset = total_read_file_size + localLogConfig.offset;
    }

    aws_json_add_num_val1(log_handler->allocator, result_data_json, "Offset", return_offset);
    aws_json_value_add_to_object(result_data_json, aws_byte_cursor_from_c_str("list"), log_list_json);
    aws_json_value_add_to_object(logReportJson, aws_byte_cursor_from_c_str("data"), result_data_json);

    struct aws_byte_buf payload_buf = aws_json_obj_to_bye_buf(log_handler->allocator, logReportJson);
    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_buf(&payload_buf);


    struct aws_string *trace_id = aws_string_new_from_c_str(log_handler->allocator, localLogConfig.traceId);
    char *pub_topic_str = iot_get_topic_with_1_param(log_handler->allocator, "sys/%s/%s/log/local/report/%s",
                                                     log_handler->mqtt_handle->product_key,
                                                     log_handler->mqtt_handle->device_name, trace_id);
    struct aws_byte_cursor public_topic = aws_byte_cursor_from_c_str(pub_topic_str);

    aws_mqtt_client_connection_publish(log_handler->mqtt_handle->mqtt_connection, &public_topic,
                                       AWS_MQTT_QOS_AT_MOST_ONCE, false, &payload_cur,
                                       _tm_mqtt_post_on_complete_fn, NULL);

    aws_byte_buf_clean_up(&payload_buf);
    aws_json_value_destroy(logReportJson);
    aws_string_destroy_secure(trace_id);
    aws_string_destroy_secure(log_dir_path);
    aws_directory_entry_iterator_destroy(iterator);


}